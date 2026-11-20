#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/noc-health-monitor"
SERVICE_USER="nocmonitor"

echo "[1/5] Creating dedicated system user (${SERVICE_USER})..."
if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

echo "[2/5] Installing application files to ${INSTALL_DIR}..."
sudo mkdir -p "${INSTALL_DIR}"
sudo cp -r ./* "${INSTALL_DIR}/"
sudo mkdir -p "${INSTALL_DIR}/data" "${INSTALL_DIR}/logs"

if [ ! -f "${INSTALL_DIR}/.env" ]; then
    sudo cp "${INSTALL_DIR}/.env.example" "${INSTALL_DIR}/.env"
    sudo chmod 600 "${INSTALL_DIR}/.env"
fi

sudo chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"

echo "[3/5] Installing systemd service..."
sudo cp "${INSTALL_DIR}/deploy/noc-monitor.service" /etc/systemd/system/noc-monitor.service
sudo systemctl daemon-reload
sudo systemctl enable noc-monitor.service

echo "[4/5] Starting noc-monitor service..."
sudo systemctl restart noc-monitor.service

echo "[5/5] Verifying service status..."
sudo systemctl --no-pager status noc-monitor.service

echo ""
echo "Done! Edit ${INSTALL_DIR}/.env to add Discord/Slack/Telegram webhooks, then run:"
echo "  sudo systemctl restart noc-monitor.service"
echo "  sudo journalctl -u noc-monitor -f"
