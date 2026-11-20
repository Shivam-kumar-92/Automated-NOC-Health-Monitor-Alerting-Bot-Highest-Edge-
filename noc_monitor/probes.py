"""Network probes: ICMP ping, TCP port checks, and concurrent target evaluation."""

from __future__ import annotations

import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from .config import MonitorConfig, TargetConfig

PORT_SERVICE_NAMES: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    123: "NTP",
    161: "SNMP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


@dataclass(frozen=True)
class ICMPResult:
    reachable: bool
    packets_sent: int
    packets_received: int
    packet_loss_pct: float
    min_ms: float | None = None
    avg_ms: float | None = None
    max_ms: float | None = None
    error: str | None = None


@dataclass(frozen=True)
class PortResult:
    port: int
    service: str
    is_open: bool
    latency_ms: float | None = None
    error: str | None = None


@dataclass(frozen=True)
class TargetCheckResult:
    timestamp: str
    name: str
    host: str
    resolved_ip: str
    role: str
    status: str  # "UP" | "DEGRADED" | "DOWN"
    icmp: ICMPResult | None
    ports: tuple[PortResult, ...]
    reasons: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "name": self.name,
            "host": self.host,
            "resolved_ip": self.resolved_ip,
            "role": self.role,
            "status": self.status,
            "icmp": asdict(self.icmp) if self.icmp else None,
            "ports": [asdict(p) for p in self.ports],
            "reasons": list(self.reasons),
        }


def resolve_host(host: str) -> tuple[str, str | None]:
    """Resolve hostname to IPv4/IPv6 address. Returns (resolved_ip, error)."""
    try:
        ip = socket.gethostbyname(host)
        return ip, None
    except socket.gaierror as exc:
        return host, f"DNS resolution failed: {exc}"


def parse_ping_output(output: str, count: int, system_name: str | None = None) -> ICMPResult:
    """Parse ping stdout from Windows, Linux, or macOS into an ICMPResult."""
    sys_name = (system_name or platform.system()).lower()

    if "windows" in sys_name:
        sent = count
        received = 0
        loss_pct = 100.0

        pkt_match = re.search(
            r"Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*(\d+)\s*\((\d+)%\s*loss\)",
            output,
            re.IGNORECASE,
        )
        if pkt_match:
            sent = int(pkt_match.group(1))
            received = int(pkt_match.group(2))
            loss_pct = float(pkt_match.group(4))

        min_ms = avg_ms = max_ms = None
        rtt_match = re.search(
            r"Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms",
            output,
            re.IGNORECASE,
        )
        if rtt_match:
            min_ms = float(rtt_match.group(1))
            max_ms = float(rtt_match.group(2))
            avg_ms = float(rtt_match.group(3))

        reachable = received > 0
        error = None if reachable else "100% packet loss (host unreachable)"
        return ICMPResult(
            reachable=reachable,
            packets_sent=sent,
            packets_received=received,
            packet_loss_pct=loss_pct,
            min_ms=min_ms,
            avg_ms=avg_ms,
            max_ms=max_ms,
            error=error,
        )

    # Linux / macOS ping output
    sent = count
    received = 0
    loss_pct = 100.0

    pkt_match = re.search(
        r"(\d+)\s+packets\s+transmitted,\s+(\d+)\s+(?:packets\s+)?received.*?(\d+(?:\.\d+)?)%\s+packet\s+loss",
        output,
        re.IGNORECASE | re.DOTALL,
    )
    if pkt_match:
        sent = int(pkt_match.group(1))
        received = int(pkt_match.group(2))
        loss_pct = float(pkt_match.group(3))

    min_ms = avg_ms = max_ms = None
    rtt_match = re.search(
        r"(?:rtt|round-trip)\s+min/avg/max(?:/\w+)?\s*=\s*(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)",
        output,
        re.IGNORECASE,
    )
    if rtt_match:
        min_ms = float(rtt_match.group(1))
        avg_ms = float(rtt_match.group(2))
        max_ms = float(rtt_match.group(3))

    reachable = received > 0
    error = None if reachable else "100% packet loss (host unreachable)"
    return ICMPResult(
        reachable=reachable,
        packets_sent=sent,
        packets_received=received,
        packet_loss_pct=loss_pct,
        min_ms=min_ms,
        avg_ms=avg_ms,
        max_ms=max_ms,
        error=error,
    )


def run_icmp_ping(host: str, count: int = 3, timeout_seconds: float = 2.0) -> ICMPResult:
    """Execute system ICMP ping and parse RTT + packet loss statistics."""
    sys_name = platform.system().lower()
    if "windows" in sys_name:
        timeout_ms = max(500, int(timeout_seconds * 1000))
        cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), host]
    elif "darwin" in sys_name:
        timeout_ms = max(500, int(timeout_seconds * 1000))
        cmd = ["ping", "-c", str(count), "-W", str(timeout_ms), host]
    else:
        timeout_sec = max(1, int(round(timeout_seconds)))
        cmd = ["ping", "-c", str(count), "-W", str(timeout_sec), host]

    overall_timeout = (count * timeout_seconds) + 5.0
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=overall_timeout,
            check=False,
        )
        combined_output = f"{completed.stdout}\n{completed.stderr}"
        return parse_ping_output(combined_output, count=count, system_name=sys_name)
    except subprocess.TimeoutExpired:
        return ICMPResult(
            reachable=False,
            packets_sent=count,
            packets_received=0,
            packet_loss_pct=100.0,
            error="ICMP ping command timed out",
        )
    except OSError as exc:
        return ICMPResult(
            reachable=False,
            packets_sent=count,
            packets_received=0,
            packet_loss_pct=100.0,
            error=f"ICMP ping execution failed: {exc}",
        )


def check_tcp_port(host: str, port: int, timeout_seconds: float = 3.0) -> PortResult:
    """Attempt a TCP 3-way handshake on host:port and measure connect latency."""
    service = PORT_SERVICE_NAMES.get(port, f"TCP-{port}")
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)
            return PortResult(
                port=port,
                service=service,
                is_open=True,
                latency_ms=elapsed_ms,
                error=None,
            )
    except socket.timeout:
        return PortResult(
            port=port,
            service=service,
            is_open=False,
            latency_ms=None,
            error=f"TCP timeout ({timeout_seconds}s)",
        )
    except OSError as exc:
        return PortResult(
            port=port,
            service=service,
            is_open=False,
            latency_ms=None,
            error=exc.strerror or str(exc),
        )


def probe_target(target: TargetConfig, config: MonitorConfig) -> TargetCheckResult:
    """Run DNS resolution, ICMP ping, and TCP port checks for a single endpoint."""
    ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    resolved_ip, dns_error = resolve_host(target.host)

    reasons: list[str] = []
    if dns_error:
        reasons.append(dns_error)
        return TargetCheckResult(
            timestamp=ts,
            name=target.name,
            host=target.host,
            resolved_ip=resolved_ip,
            role=target.role,
            status="DOWN",
            icmp=(
                ICMPResult(
                    reachable=False,
                    packets_sent=config.icmp_count,
                    packets_received=0,
                    packet_loss_pct=100.0,
                    error=dns_error,
                )
                if target.check_icmp
                else None
            ),
            ports=tuple(
                PortResult(
                    port=p,
                    service=PORT_SERVICE_NAMES.get(p, f"TCP-{p}"),
                    is_open=False,
                    error=dns_error,
                )
                for p in target.tcp_ports
            ),
            reasons=tuple(reasons),
        )

    icmp_result: ICMPResult | None = None
    if target.check_icmp:
        icmp_result = run_icmp_ping(
            resolved_ip,
            count=config.icmp_count,
            timeout_seconds=config.icmp_timeout_seconds,
        )

    port_results: list[PortResult] = []
    for port in target.tcp_ports:
        port_results.append(check_tcp_port(resolved_ip, port, timeout_seconds=config.tcp_timeout_seconds))

    # Evaluate health status against thresholds
    lat_warn = (
        target.latency_warning_ms
        if target.latency_warning_ms is not None
        else config.thresholds.latency_warning_ms
    )
    lat_crit = (
        target.latency_critical_ms
        if target.latency_critical_ms is not None
        else config.thresholds.latency_critical_ms
    )
    loss_thresh = (
        target.packet_loss_threshold_pct
        if target.packet_loss_threshold_pct is not None
        else config.thresholds.packet_loss_threshold_pct
    )

    is_down = False
    is_degraded = False

    if icmp_result is not None:
        if not icmp_result.reachable:
            is_down = True
            reasons.append(f"ICMP unreachable ({icmp_result.packet_loss_pct:.0f}% loss)")
        else:
            if icmp_result.packet_loss_pct >= loss_thresh:
                is_degraded = True
                reasons.append(
                    f"Packet loss {icmp_result.packet_loss_pct:.1f}% >= {loss_thresh:.1f}%"
                )
            if icmp_result.avg_ms is not None:
                if icmp_result.avg_ms >= lat_crit:
                    is_degraded = True
                    reasons.append(
                        f"Critical latency {icmp_result.avg_ms:.1f}ms >= {lat_crit:.1f}ms"
                    )
                elif icmp_result.avg_ms >= lat_warn:
                    is_degraded = True
                    reasons.append(
                        f"High latency {icmp_result.avg_ms:.1f}ms >= {lat_warn:.1f}ms"
                    )

    closed_ports = [p for p in port_results if not p.is_open]
    if closed_ports:
        is_down = True
        for cp in closed_ports:
            reasons.append(f"Port {cp.port}/{cp.service} DOWN ({cp.error})")

    for pr in port_results:
        if pr.is_open and pr.latency_ms is not None and pr.latency_ms >= lat_crit:
            is_degraded = True
            reasons.append(f"Port {pr.port}/{pr.service} slow ({pr.latency_ms:.1f}ms)")

    if is_down:
        status = "DOWN"
    elif is_degraded:
        status = "DEGRADED"
    else:
        status = "UP"

    return TargetCheckResult(
        timestamp=ts,
        name=target.name,
        host=target.host,
        resolved_ip=resolved_ip,
        role=target.role,
        status=status,
        icmp=icmp_result,
        ports=tuple(port_results),
        reasons=tuple(reasons),
    )


def probe_all_targets(config: MonitorConfig) -> list[TargetCheckResult]:
    """Probe all configured targets concurrently and preserve target order."""
    results_by_name: dict[str, TargetCheckResult] = {}
    worker_count = min(config.max_workers, max(1, len(config.targets)))

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        future_map = {
            pool.submit(probe_target, target, config): target.name
            for target in config.targets
        }
        for future in as_completed(future_map):
            name = future_map[future]
            results_by_name[name] = future.result()

    return [results_by_name[t.name] for t in config.targets]
