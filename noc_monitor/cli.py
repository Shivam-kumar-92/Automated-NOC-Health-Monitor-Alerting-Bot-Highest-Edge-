"""Command-line interface and monitoring daemon loop for NOC Health Monitor."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import logging
from pathlib import Path
import signal
import sys
import threading
import time

from . import __version__
from .alerter import AlertEvent, AlertStateManager, WebhookDispatcher, format_duration
from .config import MonitorConfig, load_config
from .dashboard import start_dashboard_server
from .probes import ICMPResult, PortResult, TargetCheckResult, probe_all_targets
from .storage import RotatingCSVLogger, SLAStore, setup_logging

logger = logging.getLogger("noc_monitor.cli")


def _print_sweep_table(results: list[TargetCheckResult]) -> None:
    now = results[0].timestamp if results else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"\n=== NOC Health Sweep @ {now} ===")
    header = f"{'TARGET':<22} {'IP':<16} {'STATUS':<10} {'RTT(ms)':<9} {'LOSS':<7} {'TCP PORTS'}"
    print(header)
    print("-" * max(len(header), 92))
    for r in results:
        rtt = f"{r.icmp.avg_ms:.1f}" if (r.icmp and r.icmp.avg_ms is not None) else "N/A"
        loss = f"{r.icmp.packet_loss_pct:.0f}%" if r.icmp is not None else "N/A"
        ports = (
            " ".join(f"{p.port}:{'OK' if p.is_open else 'FAIL'}" for p in r.ports)
            if r.ports
            else "ICMP-only"
        )
        print(f"{r.name:<22} {r.resolved_ip:<16} {r.status:<10} {rtt:<9} {loss:<7} {ports}")
        if r.reasons:
            print(f"   -> {'; '.join(r.reasons)}")


def _print_alert_banner(event: AlertEvent, channels: list[str]) -> None:
    ch_str = ", ".join(channels) if channels else "console-only (no webhook configured)"
    print("\n" + "!" * 76)
    print(f"  [ALERT {event.event_type}] {event.target_name} ({event.host} -> {event.resolved_ip})")
    print(f"  Timestamp (UTC) : {event.timestamp}")
    if event.event_type == "RECOVERED":
        print(f"  Down Since      : {event.down_since}")
        print(f"  Total Downtime  : {format_duration(event.downtime_seconds)}")
    else:
        print(f"  Down Timestamp  : {event.down_since or event.timestamp}")
    print(f"  TCP Ports       : {event.ports_summary}")
    if event.reasons:
        print(f"  Diagnostics     : {'; '.join(event.reasons)}")
    print(f"  Dispatched To   : {ch_str}")
    print("!" * 76)


def _print_sla_report(store: SLAStore, window_hours: float | None) -> None:
    summary = store.get_sla_summary(window_hours=window_hours)
    label = f"Last {window_hours:g}h" if window_hours is not None else "All-Time"
    print(f"\n=== NOC SLA Availability Report ({label}) ===")
    if not summary:
        print("No health check records found yet. Run `python monitor.py --once` first.")
        return

    header = (
        f"{'TARGET':<22} {'IP':<16} {'SLA %':<10} {'CHECKS':<8} "
        f"{'UP/DEG/DN':<13} {'AVG RTT':<10} {'INCIDENTS':<10} {'DOWNTIME'}"
    )
    print(header)
    print("-" * len(header))
    for s in summary:
        rtt = f"{s['avg_latency_ms']:.1f}ms" if s["avg_latency_ms"] is not None else "N/A"
        counts = f"{s['up_checks']}/{s['degraded_checks']}/{s['down_checks']}"
        print(
            f"{s['target_name']:<22} {s['resolved_ip']:<16} {s['availability_pct']:>7.3f}%  "
            f"{s['total_checks']:<8} {counts:<13} {rtt:<10} "
            f"{s['incident_count']:<10} {format_duration(s['total_downtime_sec'])}"
        )

    incidents = store.get_recent_incidents(limit=10)
    if incidents:
        print("\n--- Recent Incidents (up to 10) ---")
        for inc in incidents:
            print(
                f"#{inc['id']} [{inc['status']}/{inc['severity']}] {inc['target_name']} ({inc['resolved_ip']}) | "
                f"Start: {inc['started_at']} | End: {inc['resolved_at'] or 'OPEN'} | "
                f"Duration: {format_duration(inc['duration_seconds'])} | {inc['reason']}"
            )


def _run_test_alert(dispatcher: WebhookDispatcher) -> int:
    channels = dispatcher.configured_channels()
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    sample_down = AlertEvent(
        event_type="DOWN",
        target_name="Core-Router-01 (TEST)",
        host="router01.corp.local",
        resolved_ip="10.0.0.1",
        role="core-router",
        timestamp=now,
        down_since=now,
        latency_ms=None,
        packet_loss_pct=100.0,
        ports_summary="22/SSH: DOWN, 443/HTTPS: DOWN",
        reasons=("TEST ALERT: Simulated ICMP 100% packet loss", "Port 22/SSH DOWN (Timeout)"),
    )
    print(f"Configured webhook channels: {channels or ['none (dry-run)']}")
    down_res = dispatcher.send(sample_down)
    _print_alert_banner(sample_down, channels)
    for ch, (ok, msg) in down_res.items():
        print(f"  -> {ch} DOWN test: {'OK' if ok else 'FAILED'} ({msg})")

    sample_rec = AlertEvent(
        event_type="RECOVERED",
        target_name="Core-Router-01 (TEST)",
        host="router01.corp.local",
        resolved_ip="10.0.0.1",
        role="core-router",
        timestamp=now,
        down_since=now,
        downtime_seconds=42.0,
        latency_ms=11.4,
        packet_loss_pct=0.0,
        ports_summary="22/SSH: UP (9ms), 443/HTTPS: UP (12ms)",
        reasons=("TEST ALERT: Host recovered and passed all probes",),
    )
    rec_res = dispatcher.send(sample_rec)
    _print_alert_banner(sample_rec, channels)
    for ch, (ok, msg) in rec_res.items():
        print(f"  -> {ch} RECOVERED test: {'OK' if ok else 'FAILED'} ({msg})")

    all_ok = all(ok for ok, _ in list(down_res.values()) + list(rec_res.values()))
    return 0 if all_ok else 1


def _run_simulated_outage(
    store: SLAStore,
    csv_logger: RotatingCSVLogger,
    dispatcher: WebhookDispatcher,
) -> int:
    """Demonstrate full DOWN -> Incident -> RECOVERY -> SLA tracking lifecycle."""
    print("\nRunning simulated NOC outage & recovery demo...")
    alert_mgr = AlertStateManager(
        dispatcher=dispatcher,
        store=store,
        consecutive_failures=1,
        notify_on_degraded=True,
    )
    channels = dispatcher.configured_channels()

    t1 = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    down_result = TargetCheckResult(
        timestamp=t1,
        name="Edge-Firewall-Demo",
        host="fw-edge-01.example.net",
        resolved_ip="198.51.100.10",
        role="firewall",
        status="DOWN",
        icmp=ICMPResult(
            reachable=False,
            packets_sent=3,
            packets_received=0,
            packet_loss_pct=100.0,
            error="100% packet loss (host unreachable)",
        ),
        ports=(
            PortResult(port=22, service="SSH", is_open=False, error="TCP timeout (3.0s)"),
            PortResult(port=443, service="HTTPS", is_open=False, error="TCP timeout (3.0s)"),
        ),
        reasons=("ICMP unreachable (100% loss)", "Port 22/SSH DOWN (TCP timeout)", "Port 443/HTTPS DOWN (TCP timeout)"),
    )
    store.record_check(down_result)
    csv_logger.write_result(down_result)
    _print_sweep_table([down_result])
    ev_down = alert_mgr.process(down_result)
    if ev_down:
        _print_alert_banner(ev_down, channels)

    print("\nWaiting 2 seconds to simulate outage duration before recovery...")
    time.sleep(2.0)

    t2 = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    up_result = TargetCheckResult(
        timestamp=t2,
        name="Edge-Firewall-Demo",
        host="fw-edge-01.example.net",
        resolved_ip="198.51.100.10",
        role="firewall",
        status="UP",
        icmp=ICMPResult(
            reachable=True,
            packets_sent=3,
            packets_received=3,
            packet_loss_pct=0.0,
            min_ms=9.2,
            avg_ms=11.8,
            max_ms=14.1,
        ),
        ports=(
            PortResult(port=22, service="SSH", is_open=True, latency_ms=10.4),
            PortResult(port=443, service="HTTPS", is_open=True, latency_ms=13.2),
        ),
        reasons=(),
    )
    store.record_check(up_result)
    csv_logger.write_result(up_result)
    _print_sweep_table([up_result])
    ev_up = alert_mgr.process(up_result)
    if ev_up:
        _print_alert_banner(ev_up, channels)

    _print_sla_report(store, window_hours=None)
    return 0


def run_sweep(
    config: MonitorConfig,
    store: SLAStore,
    csv_logger: RotatingCSVLogger,
    alert_mgr: AlertStateManager,
    dispatcher: WebhookDispatcher,
) -> list[TargetCheckResult]:
    results = probe_all_targets(config)
    channels = dispatcher.configured_channels()

    for res in results:
        store.record_check(res)
        csv_logger.write_result(res)
        event = alert_mgr.process(res)
        if event is not None:
            _print_alert_banner(event, channels)

    _print_sweep_table(results)
    return results


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="monitor.py",
        description="Automated NOC Health Monitor & Alerting Bot (ICMP + TCP Ports + SLA + Webhooks)",
    )
    parser.add_argument(
        "--config",
        default="config.json",
        help="Path to JSON configuration file (default: config.json)",
    )
    parser.add_argument("--once", action="store_true", help="Run a single health check sweep and exit")
    parser.add_argument("--sla-report", action="store_true", help="Display SLA availability & incident report and exit")
    parser.add_argument(
        "--window-hours",
        type=float,
        default=None,
        help="Optional lookback window in hours for --sla-report (e.g., 24)",
    )
    parser.add_argument("--test-alert", action="store_true", help="Send a test DOWN + RECOVERY webhook alert and exit")
    parser.add_argument(
        "--simulate-outage",
        action="store_true",
        help="Simulate an outage & recovery cycle for testing/demos and exit",
    )
    parser.add_argument("--dashboard", action="store_true", help="Start embedded live NOC web dashboard")
    parser.add_argument("--dashboard-host", default="127.0.0.1", help="Dashboard bind host (default: 127.0.0.1)")
    parser.add_argument("--dashboard-port", type=int, default=8080, help="Dashboard port (default: 8080)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    config_path = Path(args.config).resolve()
    base_dir = config_path.parent
    config = load_config(config_path)

    setup_logging(config.storage, base_dir=base_dir, verbose=args.verbose)
    store = SLAStore(base_dir / config.storage.sqlite_path)
    csv_logger = RotatingCSVLogger(
        path=base_dir / config.storage.csv_log_path,
        max_bytes=config.storage.csv_max_bytes,
        backup_count=config.storage.csv_backup_count,
    )
    dispatcher = WebhookDispatcher(config.alerts)

    if args.sla_report:
        _print_sla_report(store, window_hours=args.window_hours)
        return 0

    if args.test_alert:
        return _run_test_alert(dispatcher)

    if args.simulate_outage:
        return _run_simulated_outage(store, csv_logger, dispatcher)

    alert_mgr = AlertStateManager(
        dispatcher=dispatcher,
        store=store,
        consecutive_failures=config.thresholds.consecutive_failures,
        notify_on_degraded=config.alerts.notify_on_degraded,
    )

    if args.once:
        run_sweep(config, store, csv_logger, alert_mgr, dispatcher)
        return 0

    dashboard_server = None
    if args.dashboard:
        dashboard_server = start_dashboard_server(
            store=store,
            host=args.dashboard_host,
            port=args.dashboard_port,
        )
        print(f"NOC Live Dashboard running at http://{args.dashboard_host}:{args.dashboard_port}")

    stop_event = threading.Event()

    def _handle_signal(signum: int, _frame: object) -> None:
        logger.info("Received signal %s; shutting down gracefully...", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_signal)

    channels = dispatcher.configured_channels()
    print(
        f"NOC Health Monitor v{__version__} started | Targets: {len(config.targets)} | "
        f"Interval: {config.poll_interval_seconds:g}s | Webhooks: {channels or ['console-only']}"
    )
    print(f"SQLite SLA DB : {(base_dir / config.storage.sqlite_path).resolve()}")
    print(f"Rotating CSV  : {(base_dir / config.storage.csv_log_path).resolve()}")
    print("Press Ctrl+C to stop.\n")

    try:
        while not stop_event.is_set():
            cycle_start = time.monotonic()
            try:
                run_sweep(config, store, csv_logger, alert_mgr, dispatcher)
            except Exception as exc:
                logger.exception("Unexpected error during monitoring sweep: %s", exc)

            elapsed = time.monotonic() - cycle_start
            sleep_for = max(0.5, config.poll_interval_seconds - elapsed)
            stop_event.wait(timeout=sleep_for)
    finally:
        if dashboard_server is not None:
            dashboard_server.shutdown()
            dashboard_server.server_close()
        print("\nNOC Health Monitor stopped cleanly.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
