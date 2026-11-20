"""Lightweight zero-dependency NOC web dashboard powered by http.server."""

from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .storage import SLAStore

logger = logging.getLogger("noc_monitor.dashboard")

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>NOC Health Monitor & SLA Dashboard</title>
  <style>
    :root {
      --bg: #0b1120;
      --panel: #111827;
      --border: #1f2937;
      --text: #e5e7eb;
      --muted: #9ca3af;
      --up: #22c55e;
      --degraded: #f59e0b;
      --down: #ef4444;
      --accent: #38bdf8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
      background: var(--bg);
      color: var(--text);
      padding: 24px;
      line-height: 1.5;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
    }
    h1 { font-size: 1.4rem; letter-spacing: 0.04em; color: #f8fafc; }
    .subtitle { color: var(--muted); font-size: 0.85rem; }
    .live-pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: rgba(34, 197, 94, 0.12);
      color: var(--up);
      border: 1px solid rgba(34, 197, 94, 0.35);
      padding: 6px 12px;
      border-radius: 999px;
      font-size: 0.8rem;
      font-weight: 600;
    }
    .dot {
      width: 8px; height: 8px; border-radius: 50%;
      background: var(--up);
      animation: pulse 1.8s infinite;
    }
    @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.35; } }
    .kpis {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
      margin-bottom: 24px;
    }
    .kpi {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
    }
    .kpi-label { color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.06em; }
    .kpi-val { font-size: 1.7rem; font-weight: 700; margin-top: 6px; }
    .section {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 18px;
      margin-bottom: 22px;
      overflow-x: auto;
    }
    .section h2 {
      font-size: 1rem;
      margin-bottom: 14px;
      color: #f1f5f9;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    table { width: 100%; border-collapse: collapse; font-size: 0.86rem; }
    th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); font-weight: 600; font-size: 0.76rem; text-transform: uppercase; letter-spacing: 0.05em; }
    tr:last-child td { border-bottom: none; }
    .badge {
      display: inline-block;
      padding: 2px 9px;
      border-radius: 999px;
      font-size: 0.74rem;
      font-weight: 700;
      letter-spacing: 0.04em;
    }
    .UP, .RESOLVED { background: rgba(34,197,94,0.16); color: var(--up); border: 1px solid rgba(34,197,94,0.4); }
    .DEGRADED { background: rgba(245,158,11,0.16); color: var(--degraded); border: 1px solid rgba(245,158,11,0.4); }
    .DOWN, .OPEN { background: rgba(239,68,68,0.16); color: var(--down); border: 1px solid rgba(239,68,68,0.4); }
    .port-pill {
      display: inline-block;
      margin: 2px 4px 2px 0;
      padding: 2px 7px;
      border-radius: 6px;
      font-size: 0.74rem;
      font-family: monospace;
    }
    .port-up { background: rgba(34,197,94,0.14); color: #86efac; border: 1px solid rgba(34,197,94,0.3); }
    .port-down { background: rgba(239,68,68,0.16); color: #fca5a5; border: 1px solid rgba(239,68,68,0.35); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color: var(--accent); }
    .muted { color: var(--muted); }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>NOC NETWORK HEALTH &amp; SLA MONITOR</h1>
      <div class="subtitle">Real-time ICMP, TCP Port (22/53/80/443), Packet Loss &amp; Incident Tracking</div>
    </div>
    <div class="live-pill"><span class="dot"></span><span id="refresh-status">Live &middot; Syncing...</span></div>
  </header>

  <div class="kpis" id="kpis"></div>

  <div class="section">
    <h2>Live Endpoint Telemetry <span class="subtitle" id="last-updated"></span></h2>
    <table>
      <thead>
        <tr>
          <th>Endpoint</th>
          <th>Host / IP</th>
          <th>Status</th>
          <th>ICMP Latency</th>
          <th>Packet Loss</th>
          <th>TCP Ports</th>
          <th>Diagnostics</th>
        </tr>
      </thead>
      <tbody id="endpoints-body"></tbody>
    </table>
  </div>

  <div class="section">
    <h2>SLA Availability Summary (All-Time)</h2>
    <table>
      <thead>
        <tr>
          <th>Endpoint</th>
          <th>Host / IP</th>
          <th>Availability</th>
          <th>Checks (Up/Deg/Down)</th>
          <th>Avg Latency</th>
          <th>Incidents</th>
          <th>Total Downtime</th>
        </tr>
      </thead>
      <tbody id="sla-body"></tbody>
    </table>
  </div>

  <div class="section">
    <h2>Recent Incidents &amp; Recovery Log</h2>
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Endpoint</th>
          <th>IP</th>
          <th>Severity</th>
          <th>State</th>
          <th>Started (UTC)</th>
          <th>Resolved (UTC)</th>
          <th>Duration</th>
          <th>Root Cause</th>
        </tr>
      </thead>
      <tbody id="incidents-body"></tbody>
    </table>
  </div>

  <script>
    function fmtDur(sec) {
      if (sec === null || sec === undefined) return "Ongoing";
      const s = Math.round(sec);
      const h = Math.floor(s / 3600);
      const m = Math.floor((s % 3600) / 60);
      const r = s % 60;
      if (h > 0) return `${h}h ${m}m ${r}s`;
      if (m > 0) return `${m}m ${r}s`;
      return `${r}s`;
    }

    function esc(str) {
      return String(str ?? "").replace(/[&<>"']/g, c => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
      }[c]));
    }

    async function refresh() {
      try {
        const res = await fetch("/api/overview");
        const data = await res.json();

        const checks = data.latest_checks || [];
        const sla = data.sla_summary || [];
        const incidents = data.recent_incidents || [];

        const upCount = checks.filter(c => c.status === "UP").length;
        const degCount = checks.filter(c => c.status === "DEGRADED").length;
        const downCount = checks.filter(c => c.status === "DOWN").length;
        const openInc = incidents.filter(i => i.status === "OPEN").length;
        const avgSla = sla.length
          ? (sla.reduce((acc, s) => acc + s.availability_pct, 0) / sla.length).toFixed(3) + "%"
          : "N/A";

        document.getElementById("kpis").innerHTML = `
          <div class="kpi"><div class="kpi-label">Monitored Hosts</div><div class="kpi-val">${checks.length}</div></div>
          <div class="kpi"><div class="kpi-label">Healthy (UP)</div><div class="kpi-val" style="color:var(--up)">${upCount}</div></div>
          <div class="kpi"><div class="kpi-label">Degraded</div><div class="kpi-val" style="color:var(--degraded)">${degCount}</div></div>
          <div class="kpi"><div class="kpi-label">Critical (DOWN)</div><div class="kpi-val" style="color:var(--down)">${downCount}</div></div>
          <div class="kpi"><div class="kpi-label">Fleet SLA</div><div class="kpi-val" style="color:var(--accent)">${avgSla}</div></div>
          <div class="kpi"><div class="kpi-label">Open Incidents</div><div class="kpi-val" style="color:${openInc ? 'var(--down)' : 'var(--up)'}">${openInc}</div></div>
        `;

        document.getElementById("endpoints-body").innerHTML = checks.length
          ? checks.map(c => {
              const portsHtml = (c.ports || []).map(p => {
                const cls = p.is_open ? "port-up" : "port-down";
                const extra = p.is_open && p.latency_ms !== null ? ` ${p.latency_ms}ms` : (p.is_open ? " OK" : " DOWN");
                return `<span class="port-pill ${cls}">${p.port}/${esc(p.service)}${extra}</span>`;
              }).join("") || '<span class="muted">ICMP only</span>';
              return `
                <tr>
                  <td><strong>${esc(c.target_name)}</strong><div class="muted" style="font-size:0.75rem">${esc(c.role)}</div></td>
                  <td class="mono">${esc(c.host)}<div class="muted" style="font-size:0.75rem">${esc(c.resolved_ip)}</div></td>
                  <td><span class="badge ${esc(c.status)}">${esc(c.status)}</span></td>
                  <td>${c.icmp_avg_ms !== null ? c.icmp_avg_ms.toFixed(1) + " ms" : "N/A"}</td>
                  <td>${c.icmp_loss_pct !== null ? c.icmp_loss_pct.toFixed(1) + "%" : "N/A"}</td>
                  <td>${portsHtml}</td>
                  <td class="muted">${esc(c.reasons || "Healthy")}</td>
                </tr>`;
            }).join("")
          : '<tr><td colspan="7" class="muted">Waiting for first health check sweep...</td></tr>';

        document.getElementById("sla-body").innerHTML = sla.length
          ? sla.map(s => `
              <tr>
                <td><strong>${esc(s.target_name)}</strong></td>
                <td class="mono">${esc(s.resolved_ip)}</td>
                <td><strong>${s.availability_pct.toFixed(3)}%</strong></td>
                <td>${s.total_checks} (${s.up_checks}/${s.degraded_checks}/${s.down_checks})</td>
                <td>${s.avg_latency_ms !== null ? s.avg_latency_ms.toFixed(1) + " ms" : "N/A"}</td>
                <td>${s.incident_count}</td>
                <td>${fmtDur(s.total_downtime_sec)}</td>
              </tr>`).join("")
          : '<tr><td colspan="7" class="muted">No SLA metrics collected yet.</td></tr>';

        document.getElementById("incidents-body").innerHTML = incidents.length
          ? incidents.map(i => `
              <tr>
                <td>#${i.id}</td>
                <td><strong>${esc(i.target_name)}</strong></td>
                <td class="mono">${esc(i.resolved_ip)}</td>
                <td><span class="badge ${esc(i.severity)}">${esc(i.severity)}</span></td>
                <td><span class="badge ${esc(i.status)}">${esc(i.status)}</span></td>
                <td class="mono">${esc(i.started_at)}</td>
                <td class="mono">${esc(i.resolved_at || "-")}</td>
                <td>${fmtDur(i.duration_seconds)}</td>
                <td class="muted">${esc(i.reason)}</td>
              </tr>`).join("")
          : '<tr><td colspan="9" class="muted">No incidents recorded — 100% clean operational history.</td></tr>';

        const nowStr = new Date().toISOString().replace(".000", "").slice(0, 19) + "Z";
        document.getElementById("last-updated").textContent = "Updated " + nowStr;
        document.getElementById("refresh-status").textContent = "Live · 5s Auto-Refresh";
      } catch (err) {
        document.getElementById("refresh-status").textContent = "Disconnected · Retrying...";
      }
    }

    refresh();
    setInterval(refresh, 5000);
  </script>
</body>
</html>
"""


def start_dashboard_server(store: SLAStore, host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    """Start the embedded NOC dashboard in a daemon thread and return the server handle."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            logger.debug("Dashboard HTTP: " + format, *args)

        def _send(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path in ("/", "/index.html"):
                self._send(200, "text/html; charset=utf-8", DASHBOARD_HTML.encode("utf-8"))
                return
            if self.path == "/api/overview":
                payload = {
                    "latest_checks": store.get_latest_checks(),
                    "sla_summary": store.get_sla_summary(),
                    "recent_incidents": store.get_recent_incidents(limit=25),
                }
                self._send(200, "application/json; charset=utf-8", json.dumps(payload).encode("utf-8"))
                return
            if self.path == "/healthz":
                self._send(200, "application/json; charset=utf-8", b'{"status":"ok"}')
                return
            self._send(404, "application/json; charset=utf-8", b'{"error":"Not Found"}')

    server = ThreadingHTTPServer((host, port), Handler)
    thread = threading.Thread(target=server.serve_forever, name="noc-dashboard", daemon=True)
    thread.start()
    logger.info("NOC web dashboard listening on http://%s:%d", host, port)
    return server
