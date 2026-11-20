"""Automated unit & integration tests for NOC Health Monitor."""

from __future__ import annotations

import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from noc_monitor.alerter import AlertEvent, AlertStateManager, WebhookDispatcher, format_duration
from noc_monitor.config import AlertsConfig, load_config
from noc_monitor.dashboard import start_dashboard_server
from noc_monitor.probes import ICMPResult, PortResult, TargetCheckResult, check_tcp_port, parse_ping_output
from noc_monitor.storage import CSV_HEADERS, RotatingCSVLogger, SLAStore
from urllib import request as url_request


class TestICMPParser(unittest.TestCase):
    def test_parse_linux_ping_success(self) -> None:
        sample = (
            "PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.\n"
            "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.4 ms\n"
            "64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=14.1 ms\n"
            "64 bytes from 1.1.1.1: icmp_seq=3 ttl=57 time=13.2 ms\n"
            "--- 1.1.1.1 ping statistics ---\n"
            "3 packets transmitted, 3 received, 0% packet loss, time 2003ms\n"
            "rtt min/avg/max/mdev = 12.400/13.233/14.100/0.694 ms\n"
        )
        res = parse_ping_output(sample, count=3, system_name="linux")
        self.assertTrue(res.reachable)
        self.assertEqual(res.packets_sent, 3)
        self.assertEqual(res.packets_received, 3)
        self.assertEqual(res.packet_loss_pct, 0.0)
        self.assertAlmostEqual(res.avg_ms, 13.233)

    def test_parse_windows_ping_partial_loss(self) -> None:
        sample = (
            "Pinging 8.8.8.8 with 32 bytes of data:\n"
            "Reply from 8.8.8.8: bytes=32 time=22ms TTL=118\n"
            "Request timed out.\n"
            "Reply from 8.8.8.8: bytes=32 time=28ms TTL=118\n\n"
            "Ping statistics for 8.8.8.8:\n"
            "    Packets: Sent = 3, Received = 2, Lost = 1 (33% loss),\n"
            "Approximate round trip times in milli-seconds:\n"
            "    Minimum = 22ms, Maximum = 28ms, Average = 25ms\n"
        )
        res = parse_ping_output(sample, count=3, system_name="windows")
        self.assertTrue(res.reachable)
        self.assertEqual(res.packets_received, 2)
        self.assertEqual(res.packet_loss_pct, 33.0)
        self.assertEqual(res.avg_ms, 25.0)

    def test_parse_linux_ping_unreachable(self) -> None:
        sample = (
            "--- 192.0.2.1 ping statistics ---\n"
            "3 packets transmitted, 0 received, 100% packet loss, time 2050ms\n"
        )
        res = parse_ping_output(sample, count=3, system_name="linux")
        self.assertFalse(res.reachable)
        self.assertEqual(res.packet_loss_pct, 100.0)
        self.assertIsNone(res.avg_ms)


class TestTCPProbe(unittest.TestCase):
    def test_open_and_closed_port(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        open_port = srv.getsockname()[1]

        def accept_once() -> None:
            try:
                conn, _ = srv.accept()
                conn.close()
            except OSError:
                pass

        t = threading.Thread(target=accept_once, daemon=True)
        t.start()
        try:
            open_res = check_tcp_port("127.0.0.1", open_port, timeout_seconds=1.0)
            self.assertTrue(open_res.is_open)
            self.assertIsNotNone(open_res.latency_ms)
        finally:
            t.join(timeout=2.0)
            srv.close()

        # Bind and immediately release an ephemeral non-listening socket to get a guaranteed closed port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as unused_sock:
            unused_sock.bind(("127.0.0.1", 0))
            closed_port = unused_sock.getsockname()[1]

        closed_res = check_tcp_port("127.0.0.1", closed_port, timeout_seconds=1.0)
        self.assertFalse(closed_res.is_open)
        self.assertIsNotNone(closed_res.error)


class TestStorageAndRotation(unittest.TestCase):
    def _sample_result(self, ts: str, status: str = "UP") -> TargetCheckResult:
        return TargetCheckResult(
            timestamp=ts,
            name="Core-DNS",
            host="1.1.1.1",
            resolved_ip="1.1.1.1",
            role="dns",
            status=status,
            icmp=ICMPResult(
                reachable=(status != "DOWN"),
                packets_sent=3,
                packets_received=3 if status != "DOWN" else 0,
                packet_loss_pct=0.0 if status != "DOWN" else 100.0,
                avg_ms=14.5 if status != "DOWN" else None,
            ),
            ports=(PortResult(port=53, service="DNS", is_open=(status != "DOWN"), latency_ms=12.0),),
            reasons=() if status == "UP" else ("ICMP unreachable (100% loss)",),
        )

    def test_csv_log_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "sla.csv"
            logger = RotatingCSVLogger(csv_path, max_bytes=1024, backup_count=3)
            for idx in range(30):
                logger.write_result(self._sample_result(f"2026-11-20T08:00:{idx:02d}Z", "UP"))

            backup_1 = Path(f"{csv_path}.1")
            self.assertTrue(csv_path.exists())
            self.assertTrue(backup_1.exists())
            first_line = csv_path.read_text(encoding="utf-8").splitlines()[0]
            self.assertEqual(first_line, ",".join(CSV_HEADERS))

    def test_sqlite_sla_and_alert_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SLAStore(Path(tmp) / "sla.db")
            dispatcher = WebhookDispatcher(AlertsConfig())
            dispatcher.send = MagicMock(return_value={})

            mgr = AlertStateManager(
                dispatcher=dispatcher,
                store=store,
                consecutive_failures=2,
                notify_on_degraded=True,
            )

            # 1st DOWN check -> suppressed by hysteresis (consecutive_failures=2)
            r1 = self._sample_result("2026-11-20T08:00:00Z", "DOWN")
            store.record_check(r1)
            self.assertIsNone(mgr.process(r1))

            # 2nd consecutive DOWN check -> fires DOWN alert & opens incident
            r2 = self._sample_result("2026-11-20T08:00:30Z", "DOWN")
            store.record_check(r2)
            ev_down = mgr.process(r2)
            self.assertIsNotNone(ev_down)
            self.assertEqual(ev_down.event_type, "DOWN")
            self.assertEqual(ev_down.down_since, "2026-11-20T08:00:00Z")

            # Recovery check -> fires RECOVERED alert with exact 90s downtime
            r3 = self._sample_result("2026-11-20T08:01:30Z", "UP")
            store.record_check(r3)
            ev_rec = mgr.process(r3)
            self.assertIsNotNone(ev_rec)
            self.assertEqual(ev_rec.event_type, "RECOVERED")
            self.assertEqual(ev_rec.downtime_seconds, 90.0)
            self.assertEqual(format_duration(ev_rec.downtime_seconds), "1m 30s")
            self.assertEqual(dispatcher.send.call_count, 2)

            sla = store.get_sla_summary()
            self.assertEqual(len(sla), 1)
            self.assertAlmostEqual(sla[0]["availability_pct"], 33.333, places=2)
            self.assertEqual(sla[0]["incident_count"], 1)
            self.assertEqual(sla[0]["total_downtime_sec"], 90.0)


class TestWebhookPayloadsAndDashboard(unittest.TestCase):
    def test_payload_builders(self) -> None:
        dispatcher = WebhookDispatcher(
            AlertsConfig(
                discord_webhook_url="https://discord.example/hook",
                slack_webhook_url="https://hooks.slack.example/hook",
                telegram_bot_token="123:ABC",
                telegram_chat_id="-100123",
            )
        )
        event = AlertEvent(
            event_type="DOWN",
            target_name="Edge-Router",
            host="10.0.0.1",
            resolved_ip="10.0.0.1",
            role="router",
            timestamp="2026-11-20T08:10:00Z",
            down_since="2026-11-20T08:10:00Z",
            packet_loss_pct=100.0,
            ports_summary="22/SSH: DOWN, 443/HTTPS: DOWN",
            reasons=("ICMP unreachable (100% loss)",),
        )
        discord = dispatcher.build_discord_payload(event)
        slack = dispatcher.build_slack_payload(event)
        telegram = dispatcher.build_telegram_payload(event)

        self.assertEqual(discord["embeds"][0]["color"], 0xEF4444)
        self.assertEqual(slack["attachments"][0]["color"], "#EF4444")
        self.assertIn("Edge-Router", telegram["text"])
        self.assertEqual(telegram["chat_id"], "-100123")

    def test_dashboard_api_endpoints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SLAStore(Path(tmp) / "sla.db")
            server = start_dashboard_server(store, host="127.0.0.1", port=0)
            port = server.server_address[1]
            try:
                with url_request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=3) as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(json.loads(resp.read()), {"status": "ok"})

                with url_request.urlopen(f"http://127.0.0.1:{port}/api/overview", timeout=3) as resp:
                    data = json.loads(resp.read())
                    self.assertIn("latest_checks", data)
                    self.assertIn("sla_summary", data)
                    self.assertIn("recent_incidents", data)
            finally:
                server.shutdown()
                server.server_close()

    def test_default_config_loads(self) -> None:
        cfg_path = Path(__file__).resolve().parent.parent / "config.json"
        cfg = load_config(cfg_path)
        self.assertGreaterEqual(len(cfg.targets), 1)


if __name__ == "__main__":
    unittest.main()
