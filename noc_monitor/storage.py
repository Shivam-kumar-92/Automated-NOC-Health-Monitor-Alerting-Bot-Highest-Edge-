"""Persistent SLA storage (SQLite) and automated log rotation (CSV + application logs)."""

from __future__ import annotations

from contextlib import contextmanager
import csv
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from .config import StorageConfig
from .probes import TargetCheckResult

CSV_HEADERS = [
    "timestamp_utc",
    "target_name",
    "host",
    "resolved_ip",
    "role",
    "status",
    "icmp_avg_ms",
    "icmp_packet_loss_pct",
    "open_ports",
    "closed_ports",
    "reasons",
]


def setup_logging(storage_cfg: StorageConfig, base_dir: Path, verbose: bool = False) -> logging.Logger:
    """Configure root noc_monitor logger with console output + RotatingFileHandler."""
    log_path = (base_dir / storage_cfg.app_log_path).resolve()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("noc_monitor")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )

    file_handler = RotatingFileHandler(
        filename=log_path,
        maxBytes=storage_cfg.app_log_max_bytes,
        backupCount=storage_cfg.app_log_backup_count,
        encoding="utf-8",
    )
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)
    stream_handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
    logger.addHandler(stream_handler)

    return logger


class RotatingCSVLogger:
    """Thread-safe CSV SLA event logger with automated size-based log rotation."""

    def __init__(self, path: Path, max_bytes: int = 5 * 1024 * 1024, backup_count: int = 5) -> None:
        self.path = path.resolve()
        self.max_bytes = max(1024, max_bytes)
        self.backup_count = max(1, backup_count)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_header()

    def _ensure_header(self) -> None:
        if not self.path.exists() or self.path.stat().st_size == 0:
            with self.path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(CSV_HEADERS)

    def _rotate_if_needed(self) -> None:
        if not self.path.exists():
            self._ensure_header()
            return
        if self.path.stat().st_size < self.max_bytes:
            return

        # Shift existing backups: .4 -> .5, ..., .1 -> .2, base -> .1
        for idx in range(self.backup_count - 1, 0, -1):
            src = Path(f"{self.path}.{idx}")
            dst = Path(f"{self.path}.{idx + 1}")
            if src.exists():
                if dst.exists():
                    dst.unlink()
                src.replace(dst)

        first_backup = Path(f"{self.path}.1")
        if first_backup.exists():
            first_backup.unlink()
        self.path.replace(first_backup)
        self._ensure_header()

    def write_result(self, result: TargetCheckResult) -> None:
        open_ports = ",".join(f"{p.port}/{p.service}" for p in result.ports if p.is_open)
        closed_ports = ",".join(f"{p.port}/{p.service}" for p in result.ports if not p.is_open)
        avg_ms = (
            f"{result.icmp.avg_ms:.2f}"
            if (result.icmp and result.icmp.avg_ms is not None)
            else ""
        )
        loss_pct = (
            f"{result.icmp.packet_loss_pct:.1f}"
            if result.icmp is not None
            else ""
        )

        row = [
            result.timestamp,
            result.name,
            result.host,
            result.resolved_ip,
            result.role,
            result.status,
            avg_ms,
            loss_pct,
            open_ports,
            closed_ports,
            " | ".join(result.reasons),
        ]

        with self._lock:
            self._rotate_if_needed()
            with self.path.open("a", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(row)


class SLAStore:
    """SQLite-backed store for health checks, incident lifecycles, and SLA reporting."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path.resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    target_name TEXT NOT NULL,
                    host TEXT NOT NULL,
                    resolved_ip TEXT NOT NULL,
                    role TEXT NOT NULL,
                    status TEXT NOT NULL,
                    icmp_avg_ms REAL,
                    icmp_loss_pct REAL,
                    ports_json TEXT NOT NULL,
                    reasons TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_checks_target_ts
                    ON checks (target_name, timestamp DESC);

                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_name TEXT NOT NULL,
                    host TEXT NOT NULL,
                    resolved_ip TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    resolved_at TEXT,
                    duration_seconds REAL,
                    reason TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_incidents_target_status
                    ON incidents (target_name, status);
                """
            )

    def record_check(self, result: TargetCheckResult) -> None:
        ports_payload = json.dumps(
            [
                {
                    "port": p.port,
                    "service": p.service,
                    "is_open": p.is_open,
                    "latency_ms": p.latency_ms,
                    "error": p.error,
                }
                for p in result.ports
            ]
        )
        avg_ms = result.icmp.avg_ms if result.icmp else None
        loss_pct = result.icmp.packet_loss_pct if result.icmp else None

        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO checks (
                    timestamp, target_name, host, resolved_ip, role,
                    status, icmp_avg_ms, icmp_loss_pct, ports_json, reasons
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.timestamp,
                    result.name,
                    result.host,
                    result.resolved_ip,
                    result.role,
                    result.status,
                    avg_ms,
                    loss_pct,
                    ports_payload,
                    " | ".join(result.reasons),
                ),
            )

    def open_incident(
        self,
        target_name: str,
        host: str,
        resolved_ip: str,
        severity: str,
        reason: str,
        started_at: str,
    ) -> int:
        """Create or update an open incident for a target."""
        with self._lock, self._connect() as conn:
            existing = conn.execute(
                "SELECT id, severity FROM incidents WHERE target_name = ? AND status = 'OPEN' ORDER BY id DESC LIMIT 1",
                (target_name,),
            ).fetchone()
            if existing:
                # Escalate DEGRADED -> DOWN if needed
                if existing["severity"] != severity:
                    conn.execute(
                        "UPDATE incidents SET severity = ?, reason = ? WHERE id = ?",
                        (severity, reason, existing["id"]),
                    )
                return int(existing["id"])

            cur = conn.execute(
                """
                INSERT INTO incidents (
                    target_name, host, resolved_ip, severity, status, started_at, reason
                ) VALUES (?, ?, ?, ?, 'OPEN', ?, ?)
                """,
                (target_name, host, resolved_ip, severity, started_at, reason),
            )
            return int(cur.lastrowid)

    def resolve_incident(self, target_name: str, resolved_at: str) -> dict[str, Any] | None:
        """Close the active incident for a target and compute exact downtime duration."""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM incidents WHERE target_name = ? AND status = 'OPEN' ORDER BY id DESC LIMIT 1",
                (target_name,),
            ).fetchone()
            if not row:
                return None

            start_dt = _parse_iso(row["started_at"])
            end_dt = _parse_iso(resolved_at)
            duration_sec = max(0.0, round((end_dt - start_dt).total_seconds(), 2))

            conn.execute(
                """
                UPDATE incidents
                SET status = 'RESOLVED', resolved_at = ?, duration_seconds = ?
                WHERE id = ?
                """,
                (resolved_at, duration_sec, row["id"]),
            )
            return {
                "id": row["id"],
                "target_name": row["target_name"],
                "host": row["host"],
                "resolved_ip": row["resolved_ip"],
                "severity": row["severity"],
                "started_at": row["started_at"],
                "resolved_at": resolved_at,
                "duration_seconds": duration_sec,
                "reason": row["reason"],
            }

    def get_latest_checks(self) -> list[dict[str, Any]]:
        """Return the latest recorded check row per target."""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT c.*
                FROM checks c
                INNER JOIN (
                    SELECT target_name, MAX(id) AS max_id
                    FROM checks
                    GROUP BY target_name
                ) latest ON c.id = latest.max_id
                ORDER BY c.target_name ASC
                """
            ).fetchall()

        results: list[dict[str, Any]] = []
        for r in rows:
            item = dict(r)
            item["ports"] = json.loads(item.pop("ports_json"))
            results.append(item)
        return results

    def get_recent_incidents(self, limit: int = 25) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM incidents ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_sla_summary(self, window_hours: float | None = None) -> list[dict[str, Any]]:
        """Calculate SLA availability %, latency, loss, and downtime per target."""
        params: list[Any] = []
        where_checks = ""
        where_inc = ""
        if window_hours is not None:
            cutoff = (
                datetime.now(timezone.utc) - timedelta(hours=window_hours)
            ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            where_checks = "WHERE timestamp >= ?"
            where_inc = "WHERE started_at >= ?"
            params.append(cutoff)

        with self._lock, self._connect() as conn:
            check_rows = conn.execute(
                f"""
                SELECT
                    target_name,
                    MAX(host) AS host,
                    MAX(resolved_ip) AS resolved_ip,
                    COUNT(*) AS total_checks,
                    SUM(CASE WHEN status = 'UP' THEN 1 ELSE 0 END) AS up_checks,
                    SUM(CASE WHEN status = 'DEGRADED' THEN 1 ELSE 0 END) AS degraded_checks,
                    SUM(CASE WHEN status = 'DOWN' THEN 1 ELSE 0 END) AS down_checks,
                    AVG(icmp_avg_ms) AS avg_latency_ms,
                    AVG(icmp_loss_pct) AS avg_loss_pct
                FROM checks
                {where_checks}
                GROUP BY target_name
                ORDER BY target_name ASC
                """,
                params,
            ).fetchall()

            inc_rows = conn.execute(
                f"""
                SELECT
                    target_name,
                    COUNT(*) AS incident_count,
                    SUM(CASE WHEN status = 'OPEN' THEN 1 ELSE 0 END) AS open_incidents,
                    COALESCE(SUM(duration_seconds), 0.0) AS total_downtime_sec
                FROM incidents
                {where_inc}
                GROUP BY target_name
                """,
                params,
            ).fetchall()

        inc_map = {r["target_name"]: dict(r) for r in inc_rows}
        summary: list[dict[str, Any]] = []
        for row in check_rows:
            total = int(row["total_checks"])
            down = int(row["down_checks"])
            # Standard SLA availability = (Total - Down) / Total * 100
            availability_pct = round(((total - down) / total) * 100.0, 3) if total > 0 else 100.0
            inc = inc_map.get(row["target_name"], {})
            summary.append(
                {
                    "target_name": row["target_name"],
                    "host": row["host"],
                    "resolved_ip": row["resolved_ip"],
                    "total_checks": total,
                    "up_checks": int(row["up_checks"]),
                    "degraded_checks": int(row["degraded_checks"]),
                    "down_checks": down,
                    "availability_pct": availability_pct,
                    "avg_latency_ms": (
                        round(float(row["avg_latency_ms"]), 2)
                        if row["avg_latency_ms"] is not None
                        else None
                    ),
                    "avg_loss_pct": (
                        round(float(row["avg_loss_pct"]), 2)
                        if row["avg_loss_pct"] is not None
                        else None
                    ),
                    "incident_count": int(inc.get("incident_count", 0)),
                    "open_incidents": int(inc.get("open_incidents", 0)),
                    "total_downtime_sec": round(float(inc.get("total_downtime_sec", 0.0)), 2),
                }
            )
        return summary


def _parse_iso(ts: str) -> datetime:
    cleaned = ts.replace("Z", "+00:00")
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
