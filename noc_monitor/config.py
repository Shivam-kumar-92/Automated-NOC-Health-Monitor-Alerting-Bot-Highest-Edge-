"""Configuration loader and validation for NOC Health Monitor."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class TargetConfig:
    name: str
    host: str
    role: str = "endpoint"
    check_icmp: bool = True
    tcp_ports: tuple[int, ...] = (80, 443)
    latency_warning_ms: float | None = None
    latency_critical_ms: float | None = None
    packet_loss_threshold_pct: float | None = None


@dataclass(frozen=True)
class ThresholdsConfig:
    latency_warning_ms: float = 120.0
    latency_critical_ms: float = 250.0
    packet_loss_threshold_pct: float = 20.0
    consecutive_failures: int = 2


@dataclass(frozen=True)
class AlertsConfig:
    discord_webhook_url: str = ""
    slack_webhook_url: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    notify_on_degraded: bool = True
    request_timeout_seconds: float = 8.0


@dataclass(frozen=True)
class StorageConfig:
    sqlite_path: str = "data/sla_metrics.db"
    csv_log_path: str = "logs/sla_events.csv"
    csv_max_bytes: int = 5 * 1024 * 1024  # 5 MB
    csv_backup_count: int = 5
    app_log_path: str = "logs/noc_monitor.log"
    app_log_max_bytes: int = 5 * 1024 * 1024  # 5 MB
    app_log_backup_count: int = 5


@dataclass(frozen=True)
class MonitorConfig:
    poll_interval_seconds: float = 30.0
    icmp_count: int = 3
    icmp_timeout_seconds: float = 2.0
    tcp_timeout_seconds: float = 3.0
    max_workers: int = 10
    thresholds: ThresholdsConfig = field(default_factory=ThresholdsConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    targets: tuple[TargetConfig, ...] = ()


def load_dotenv(env_path: Path) -> None:
    """Load simple KEY=VALUE pairs from a .env file without overriding existing env vars."""
    if not env_path.is_file():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _env_or_cfg(env_name: str, cfg_value: Any) -> str:
    env_val = os.environ.get(env_name, "").strip()
    if env_val:
        return env_val
    return str(cfg_value or "").strip()


def load_config(config_path: str | Path) -> MonitorConfig:
    """Load and validate monitor configuration from JSON + environment overrides."""
    path = Path(config_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    # Load .env located next to the config file if present
    load_dotenv(path.parent / ".env")

    with path.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)

    th_raw = raw.get("thresholds", {})
    thresholds = ThresholdsConfig(
        latency_warning_ms=float(th_raw.get("latency_warning_ms", 120.0)),
        latency_critical_ms=float(th_raw.get("latency_critical_ms", 250.0)),
        packet_loss_threshold_pct=float(th_raw.get("packet_loss_threshold_pct", 20.0)),
        consecutive_failures=max(1, int(th_raw.get("consecutive_failures", 2))),
    )

    al_raw = raw.get("alerts", {})
    alerts = AlertsConfig(
        discord_webhook_url=_env_or_cfg("DISCORD_WEBHOOK_URL", al_raw.get("discord_webhook_url")),
        slack_webhook_url=_env_or_cfg("SLACK_WEBHOOK_URL", al_raw.get("slack_webhook_url")),
        telegram_bot_token=_env_or_cfg("TELEGRAM_BOT_TOKEN", al_raw.get("telegram_bot_token")),
        telegram_chat_id=_env_or_cfg("TELEGRAM_CHAT_ID", al_raw.get("telegram_chat_id")),
        notify_on_degraded=bool(al_raw.get("notify_on_degraded", True)),
        request_timeout_seconds=float(al_raw.get("request_timeout_seconds", 8.0)),
    )

    st_raw = raw.get("storage", {})
    storage = StorageConfig(
        sqlite_path=str(st_raw.get("sqlite_path", "data/sla_metrics.db")),
        csv_log_path=str(st_raw.get("csv_log_path", "logs/sla_events.csv")),
        csv_max_bytes=max(1024, int(st_raw.get("csv_max_bytes", 5 * 1024 * 1024))),
        csv_backup_count=max(1, int(st_raw.get("csv_backup_count", 5))),
        app_log_path=str(st_raw.get("app_log_path", "logs/noc_monitor.log")),
        app_log_max_bytes=max(1024, int(st_raw.get("app_log_max_bytes", 5 * 1024 * 1024))),
        app_log_backup_count=max(1, int(st_raw.get("app_log_backup_count", 5))),
    )

    targets: list[TargetConfig] = []
    for idx, t in enumerate(raw.get("targets", [])):
        if "name" not in t or "host" not in t:
            raise ValueError(f"Target at index {idx} must include 'name' and 'host'.")
        ports = tuple(int(p) for p in t.get("tcp_ports", []))
        for p in ports:
            if not (1 <= p <= 65535):
                raise ValueError(f"Invalid TCP port {p} for target '{t['name']}'.")
        targets.append(
            TargetConfig(
                name=str(t["name"]),
                host=str(t["host"]).strip(),
                role=str(t.get("role", "endpoint")),
                check_icmp=bool(t.get("check_icmp", True)),
                tcp_ports=ports,
                latency_warning_ms=(
                    float(t["latency_warning_ms"]) if t.get("latency_warning_ms") is not None else None
                ),
                latency_critical_ms=(
                    float(t["latency_critical_ms"]) if t.get("latency_critical_ms") is not None else None
                ),
                packet_loss_threshold_pct=(
                    float(t["packet_loss_threshold_pct"])
                    if t.get("packet_loss_threshold_pct") is not None
                    else None
                ),
            )
        )

    if not targets:
        raise ValueError("Configuration must define at least one target in 'targets'.")

    return MonitorConfig(
        poll_interval_seconds=max(2.0, float(raw.get("poll_interval_seconds", 30.0))),
        icmp_count=max(1, int(raw.get("icmp_count", 3))),
        icmp_timeout_seconds=max(0.5, float(raw.get("icmp_timeout_seconds", 2.0))),
        tcp_timeout_seconds=max(0.5, float(raw.get("tcp_timeout_seconds", 3.0))),
        max_workers=max(1, int(raw.get("max_workers", 10))),
        thresholds=thresholds,
        alerts=alerts,
        storage=storage,
        targets=tuple(targets),
    )
