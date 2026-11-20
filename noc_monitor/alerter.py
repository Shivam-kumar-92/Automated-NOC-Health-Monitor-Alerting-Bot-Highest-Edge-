"""Stateful NOC alerting engine and Discord / Slack / Telegram webhook dispatcher."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib import error as url_error
from urllib import request as url_request

from .config import AlertsConfig
from .probes import TargetCheckResult
from .storage import SLAStore

logger = logging.getLogger("noc_monitor.alerter")


@dataclass(frozen=True)
class AlertEvent:
    event_type: str  # "DOWN" | "DEGRADED" | "RECOVERED"
    target_name: str
    host: str
    resolved_ip: str
    role: str
    timestamp: str
    down_since: str | None = None
    downtime_seconds: float | None = None
    latency_ms: float | None = None
    packet_loss_pct: float | None = None
    ports_summary: str = "N/A"
    reasons: tuple[str, ...] = ()


@dataclass
class _TargetAlertState:
    alerted_status: str = "UP"  # "UP" | "DEGRADED" | "DOWN"
    consecutive_down: int = 0
    consecutive_degraded: int = 0
    incident_started_at: str | None = None


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "N/A"
    total = int(round(max(0.0, seconds)))
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def summarize_ports(result: TargetCheckResult) -> str:
    if not result.ports:
        return "ICMP only"
    parts = []
    for p in result.ports:
        state = f"UP ({p.latency_ms:.0f}ms)" if (p.is_open and p.latency_ms is not None) else ("UP" if p.is_open else "DOWN")
        parts.append(f"{p.port}/{p.service}: {state}")
    return ", ".join(parts)


class WebhookDispatcher:
    """Delivers structured NOC alerts to Discord, Slack, and Telegram webhooks."""

    def __init__(self, config: AlertsConfig) -> None:
        self.config = config

    def configured_channels(self) -> list[str]:
        channels: list[str] = []
        if self.config.discord_webhook_url:
            channels.append("discord")
        if self.config.slack_webhook_url:
            channels.append("slack")
        if self.config.telegram_bot_token and self.config.telegram_chat_id:
            channels.append("telegram")
        return channels

    def build_discord_payload(self, event: AlertEvent) -> dict[str, Any]:
        color_map = {"DOWN": 0xEF4444, "DEGRADED": 0xF59E0B, "RECOVERED": 0x22C55E}
        icon_map = {"DOWN": "CRITICAL OUTAGE", "DEGRADED": "PERFORMANCE DEGRADED", "RECOVERED": "HOST RECOVERED"}
        title = f"[NOC {icon_map.get(event.event_type, event.event_type)}] {event.target_name}"

        fields: list[dict[str, Any]] = [
            {"name": "Host / IP", "value": f"`{event.host}` (`{event.resolved_ip}`)", "inline": True},
            {"name": "Role", "value": event.role, "inline": True},
            {"name": "Event Time (UTC)", "value": f"`{event.timestamp}`", "inline": True},
        ]

        if event.event_type == "RECOVERED":
            fields.append({"name": "Down Since (UTC)", "value": f"`{event.down_since or 'N/A'}`", "inline": True})
            fields.append({"name": "Total Downtime", "value": f"**{format_duration(event.downtime_seconds)}**", "inline": True})
        else:
            fields.append({"name": "Down Timestamp (UTC)", "value": f"`{event.down_since or event.timestamp}`", "inline": True})

        latency_str = f"{event.latency_ms:.1f} ms" if event.latency_ms is not None else "N/A"
        loss_str = f"{event.packet_loss_pct:.1f}%" if event.packet_loss_pct is not None else "N/A"
        fields.append({"name": "Latency / Packet Loss", "value": f"{latency_str} / {loss_str}", "inline": True})
        fields.append({"name": "TCP Ports", "value": event.ports_summary, "inline": False})

        if event.reasons:
            fields.append({"name": "Diagnostics", "value": "\n".join(f"- {r}" for r in event.reasons), "inline": False})

        return {
            "username": "NOC Health Monitor",
            "embeds": [
                {
                    "title": title,
                    "color": color_map.get(event.event_type, 0x3B82F6),
                    "fields": fields,
                    "footer": {"text": "Automated NOC Health & SLA Monitor"},
                    "timestamp": event.timestamp,
                }
            ],
        }

    def build_slack_payload(self, event: AlertEvent) -> dict[str, Any]:
        color_map = {"DOWN": "#EF4444", "DEGRADED": "#F59E0B", "RECOVERED": "#22C55E"}
        header = f"*[NOC {event.event_type}] {event.target_name}*"

        lines = [
            f"*Host / IP:* `{event.host}` (`{event.resolved_ip}`) | *Role:* {event.role}",
            f"*Timestamp (UTC):* `{event.timestamp}`",
        ]
        if event.event_type == "RECOVERED":
            lines.append(
                f"*Down Since:* `{event.down_since or 'N/A'}` | *Downtime Duration:* *{format_duration(event.downtime_seconds)}*"
            )
        else:
            lines.append(f"*Down Timestamp:* `{event.down_since or event.timestamp}`")

        latency_str = f"{event.latency_ms:.1f}ms" if event.latency_ms is not None else "N/A"
        loss_str = f"{event.packet_loss_pct:.1f}%" if event.packet_loss_pct is not None else "N/A"
        lines.append(f"*ICMP:* {latency_str} | *Packet Loss:* {loss_str}")
        lines.append(f"*TCP Ports:* {event.ports_summary}")
        if event.reasons:
            lines.append("*Details:* " + "; ".join(event.reasons))

        return {
            "attachments": [
                {
                    "color": color_map.get(event.event_type, "#3B82F6"),
                    "blocks": [
                        {"type": "section", "text": {"type": "mrkdwn", "text": header}},
                        {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}},
                    ],
                }
            ]
        }

    def build_telegram_payload(self, event: AlertEvent) -> dict[str, Any]:
        badge = {"DOWN": "[DOWN]", "DEGRADED": "[DEGRADED]", "RECOVERED": "[RECOVERED]"}.get(
            event.event_type, f"[{event.event_type}]"
        )
        latency_str = f"{event.latency_ms:.1f} ms" if event.latency_ms is not None else "N/A"
        loss_str = f"{event.packet_loss_pct:.1f}%" if event.packet_loss_pct is not None else "N/A"

        lines = [
            f"<b>NOC ALERT {badge} - {_html_escape(event.target_name)}</b>",
            f"<b>Host / IP:</b> <code>{_html_escape(event.host)}</code> (<code>{_html_escape(event.resolved_ip)}</code>)",
            f"<b>Role:</b> {_html_escape(event.role)}",
            f"<b>Timestamp (UTC):</b> <code>{_html_escape(event.timestamp)}</code>",
        ]
        if event.event_type == "RECOVERED":
            lines.append(f"<b>Down Since:</b> <code>{_html_escape(event.down_since or 'N/A')}</code>")
            lines.append(f"<b>Total Downtime:</b> <b>{format_duration(event.downtime_seconds)}</b>")
        else:
            lines.append(f"<b>Down Timestamp:</b> <code>{_html_escape(event.down_since or event.timestamp)}</code>")

        lines.append(f"<b>Latency / Loss:</b> {latency_str} / {loss_str}")
        lines.append(f"<b>TCP Ports:</b> {_html_escape(event.ports_summary)}")
        if event.reasons:
            lines.append("<b>Details:</b> " + _html_escape("; ".join(event.reasons)))

        return {
            "chat_id": self.config.telegram_chat_id,
            "text": "\n".join(lines),
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }

    def _post_json(self, url: str, payload: dict[str, Any]) -> tuple[bool, str]:
        data = json.dumps(payload).encode("utf-8")
        req = url_request.Request(
            url=url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "NOC-Health-Monitor/1.0",
            },
            method="POST",
        )
        try:
            with url_request.urlopen(req, timeout=self.config.request_timeout_seconds) as resp:
                status = getattr(resp, "status", 200)
                if 200 <= status < 300:
                    return True, f"HTTP {status}"
                return False, f"Unexpected HTTP {status}"
        except url_error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="ignore")[:200]
            except Exception:
                pass
            return False, f"HTTP {exc.code}: {body or exc.reason}"
        except Exception as exc:
            return False, str(exc)

    def send(self, event: AlertEvent) -> dict[str, tuple[bool, str]]:
        """Dispatch an AlertEvent to all configured channels."""
        outcomes: dict[str, tuple[bool, str]] = {}

        if self.config.discord_webhook_url:
            ok, msg = self._post_json(self.config.discord_webhook_url, self.build_discord_payload(event))
            outcomes["discord"] = (ok, msg)
            logger.info("Discord alert (%s %s): %s - %s", event.event_type, event.target_name, ok, msg)

        if self.config.slack_webhook_url:
            ok, msg = self._post_json(self.config.slack_webhook_url, self.build_slack_payload(event))
            outcomes["slack"] = (ok, msg)
            logger.info("Slack alert (%s %s): %s - %s", event.event_type, event.target_name, ok, msg)

        if self.config.telegram_bot_token and self.config.telegram_chat_id:
            tg_url = f"https://api.telegram.org/bot{self.config.telegram_bot_token}/sendMessage"
            ok, msg = self._post_json(tg_url, self.build_telegram_payload(event))
            outcomes["telegram"] = (ok, msg)
            logger.info("Telegram alert (%s %s): %s - %s", event.event_type, event.target_name, ok, msg)

        if not outcomes:
            logger.info(
                "Alert triggered (no external webhook configured): %s %s (%s) - %s",
                event.event_type,
                event.target_name,
                event.resolved_ip,
                "; ".join(event.reasons) or "Recovered",
            )

        return outcomes


class AlertStateManager:
    """Tracks endpoint states, prevents flapping, manages incidents, and emits alerts."""

    def __init__(
        self,
        dispatcher: WebhookDispatcher,
        store: SLAStore,
        consecutive_failures: int = 2,
        notify_on_degraded: bool = True,
    ) -> None:
        self.dispatcher = dispatcher
        self.store = store
        self.consecutive_failures = max(1, consecutive_failures)
        self.notify_on_degraded = notify_on_degraded
        self._states: dict[str, _TargetAlertState] = {}

    def process(self, result: TargetCheckResult) -> AlertEvent | None:
        """Evaluate a check result, update SQLite incident state, and send webhook if transitioned."""
        state = self._states.setdefault(result.name, _TargetAlertState())
        avg_ms = result.icmp.avg_ms if result.icmp else None
        loss_pct = result.icmp.packet_loss_pct if result.icmp else None
        ports_summary = summarize_ports(result)
        reason_str = "; ".join(result.reasons) if result.reasons else "Health threshold breached"

        if result.status == "DOWN":
            state.consecutive_down += 1
            state.consecutive_degraded = 0
            if state.incident_started_at is None:
                state.incident_started_at = result.timestamp

            if state.alerted_status != "DOWN" and state.consecutive_down >= self.consecutive_failures:
                self.store.open_incident(
                    target_name=result.name,
                    host=result.host,
                    resolved_ip=result.resolved_ip,
                    severity="DOWN",
                    reason=reason_str,
                    started_at=state.incident_started_at,
                )
                state.alerted_status = "DOWN"
                event = AlertEvent(
                    event_type="DOWN",
                    target_name=result.name,
                    host=result.host,
                    resolved_ip=result.resolved_ip,
                    role=result.role,
                    timestamp=result.timestamp,
                    down_since=state.incident_started_at,
                    latency_ms=avg_ms,
                    packet_loss_pct=loss_pct,
                    ports_summary=ports_summary,
                    reasons=result.reasons,
                )
                self.dispatcher.send(event)
                return event
            return None

        if result.status == "DEGRADED":
            state.consecutive_degraded += 1
            state.consecutive_down = 0
            if state.incident_started_at is None:
                state.incident_started_at = result.timestamp

            if (
                self.notify_on_degraded
                and state.alerted_status == "UP"
                and state.consecutive_degraded >= self.consecutive_failures
            ):
                self.store.open_incident(
                    target_name=result.name,
                    host=result.host,
                    resolved_ip=result.resolved_ip,
                    severity="DEGRADED",
                    reason=reason_str,
                    started_at=state.incident_started_at,
                )
                state.alerted_status = "DEGRADED"
                event = AlertEvent(
                    event_type="DEGRADED",
                    target_name=result.name,
                    host=result.host,
                    resolved_ip=result.resolved_ip,
                    role=result.role,
                    timestamp=result.timestamp,
                    down_since=state.incident_started_at,
                    latency_ms=avg_ms,
                    packet_loss_pct=loss_pct,
                    ports_summary=ports_summary,
                    reasons=result.reasons,
                )
                self.dispatcher.send(event)
                return event
            return None

        # Status == "UP"
        state.consecutive_down = 0
        state.consecutive_degraded = 0

        if state.alerted_status in ("DOWN", "DEGRADED"):
            resolved = self.store.resolve_incident(result.name, result.timestamp)
            down_since = resolved["started_at"] if resolved else state.incident_started_at
            duration_sec = resolved["duration_seconds"] if resolved else 0.0
            state.alerted_status = "UP"
            state.incident_started_at = None

            event = AlertEvent(
                event_type="RECOVERED",
                target_name=result.name,
                host=result.host,
                resolved_ip=result.resolved_ip,
                role=result.role,
                timestamp=result.timestamp,
                down_since=down_since,
                downtime_seconds=duration_sec,
                latency_ms=avg_ms,
                packet_loss_pct=loss_pct,
                ports_summary=ports_summary,
                reasons=("All ICMP and TCP checks passed",),
            )
            self.dispatcher.send(event)
            return event

        state.incident_started_at = None
        return None


def _html_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
