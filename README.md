# Automated NOC Health Monitor & Alerting Bot

A lightweight, **zero-dependency** Python network monitoring and SLA tracking daemon built for Linux VMs, AWS EC2 instances, and local workstations. It continuously probes critical network endpoints using **ICMP ping** and **TCP port checks (`22`, `53`, `80`, `443`, and custom ports)**, tracks uptime/downtime in **SQLite + automatically rotating CSV logs**, serves an optional **live NOC web dashboard**, and fires instant **Discord, Slack, and Telegram webhook alerts** on outage, latency spikes, packet loss, and recovery.

---

## Architecture

```text
                       +----------------------------+
                       |   config.json  +  .env     |
                       +-------------+--------------+
                                     |
                                     v
                  +--------------------------------------+
                  |  Concurrent Probe Engine (Threads)   |
                  |  - ICMP Ping (RTT + Packet Loss %)   |
                  |  - TCP Handshake (22, 53, 80, 443)   |
                  |  - DNS Host-to-IP Resolution         |
                  +--------+------------------+----------+
                           |                  |
                           v                  v
          +-------------------------+  +-------------------------------+
          |  SLA Persistence Layer  |  |  Stateful Alerting Engine     |
          |  - SQLite (checks &     |  |  - Hysteresis (anti-flapping) |
          |    incidents w/ MTTR)   |  |  - DOWN / DEGRADED / RECOVERED|
          |  - Rotating CSV Logs    |  |  - Host IP, Down Timestamp,   |
          |  - Rotating App Logs    |  |    & Total Downtime Duration  |
          +-----------+-------------+  +---------------+---------------+
                      |                                |
                      v                                v
          +-------------------------+  +-------------------------------+
          |  Live NOC Web Dashboard |  |  Multi-Channel Webhooks       |
          |  http://localhost:8080  |  |  - Discord Embeds             |
          |  (/ & /api/overview)    |  |  - Slack Attachments          |
          +-------------------------+  |  - Telegram Bot API           |
                                       +-------------------------------+
```

---

## Key Features

- **ICMP Ping + TCP Port Monitoring**: Measures min/avg/max RTT, packet loss %, and TCP 3-way handshake latency across ports `22` (SSH), `53` (DNS), `80` (HTTP), `443` (HTTPS), or any custom port.
- **Anti-Flapping Alert State Machine**: Requires configurable `consecutive_failures` before paging, avoiding false alarms from single-packet jitter, and automatically dispatches **Recovery Notifications** with exact downtime duration.
- **Instant Multi-Channel Webhooks**: Rich alerts to **Discord**, **Slack**, and **Telegram** including **Host IP**, **Down Timestamp (UTC)**, **Recovery Timestamp**, **Total Downtime**, **Latency/Packet Loss**, and **Per-Port Status**.
- **Automated Log Rotation & SLA Tracking**:
  - **SQLite** (`data/sla_metrics.db`) records every check and open/resolved incident to calculate SLA availability % and MTTR.
  - **Rotating CSV Logs** (`logs/sla_events.csv`) automatically rotate on size limit (`csv_max_bytes`, `csv_backup_count`) with headers preserved on every new file.
  - **Rotating App Logs** (`logs/noc_monitor.log`) powered by `RotatingFileHandler`.
- **Embedded NOC Dashboard**: Optional zero-dependency dark-mode wallboard (`--dashboard`) showing live host health, TCP port pills, SLA availability %, and incident history.
- **Production Linux / AWS EC2 Ready**: Ships with a hardened `systemd` service unit (`deploy/noc-monitor.service`), automated Linux installer (`deploy/install_linux.sh`), and `Dockerfile`.

---

## Quick Start

Requires **Python 3.10+** (zero external `pip` packages required).

```bash
cd noc-health-monitor

# 1. Run a single live health-check sweep across configured endpoints
python monitor.py --once

# 2. Simulate an outage & recovery cycle (great for demos & testing alerts)
python monitor.py --simulate-outage

# 3. View SLA availability & incident report
python monitor.py --sla-report

# 4. Run continuous monitoring + Live NOC Web Dashboard on http://127.0.0.1:8080
python monitor.py --dashboard
```

---

## Configuring Real-Time Webhook Alerts

Copy `.env.example` to `.env` and fill in one or more channels (secrets stay out of Git):

```bash
cp .env.example .env
```

```env
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T000/B000/XXXX
TELEGRAM_BOT_TOKEN=123456789:AAExampleBotToken
TELEGRAM_CHAT_ID=-1001234567890
```

Verify your webhook setup immediately with a synthetic DOWN + RECOVERY test pair:

```bash
python monitor.py --test-alert
```

---

## Deploying on a Linux VM or AWS EC2

```bash
# On Ubuntu / Amazon Linux / Debian EC2:
chmod +x deploy/install_linux.sh
./deploy/install_linux.sh

# Add your Discord/Slack/Telegram secrets:
sudo nano /opt/noc-health-monitor/.env
sudo systemctl restart noc-monitor.service

# Stream live service logs:
sudo journalctl -u noc-monitor -f
```

Or run via Docker:

```bash
docker build -t noc-health-monitor .
docker run -d --name noc-monitor --env-file .env -p 8080:8080 noc-health-monitor
```

---

## Running Automated Tests

```bash
python -m unittest discover -s tests -v
```

---

## CLI Reference

| Flag | Description |
| --- | --- |
| `--config PATH` | Path to JSON config file (default: `config.json`) |
| `--once` | Execute a single monitoring sweep, log to SQLite + CSV, and exit |
| `--dashboard` | Launch embedded NOC web dashboard while monitoring |
| `--dashboard-host HOST` | Bind address for web dashboard (default: `127.0.0.1`) |
| `--dashboard-port PORT` | Port for web dashboard (default: `8080`) |
| `--sla-report` | Print SLA uptime %, latency, and recent incidents from SQLite |
| `--window-hours N` | Filter `--sla-report` to the last `N` hours (e.g. `--window-hours 24`) |
| `--test-alert` | Send test `DOWN` and `RECOVERED` alerts to configured webhooks |
| `--simulate-outage` | Run a full simulated outage -> alert -> recovery -> SLA demo |
| `--verbose` | Enable debug-level console and file logging |
