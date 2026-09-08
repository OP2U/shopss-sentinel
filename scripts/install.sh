#!/usr/bin/env bash
# Copyright 2026 OP2U
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer with sudo."
  exit 1
fi

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mkdir -p /opt/shopss-sentinel
mkdir -p /etc/shopss-sentinel
mkdir -p /var/lib/shopss-sentinel

rm -rf /opt/shopss-sentinel/sentinel
cp -r "${SOURCE_DIR}/sentinel" /opt/shopss-sentinel/
cp "${SOURCE_DIR}/systemd/shopss-sentinel.service" /etc/systemd/system/shopss-sentinel.service

if [[ ! -f /etc/shopss-sentinel/config.json ]]; then
  cp "${SOURCE_DIR}/config.example.json" /etc/shopss-sentinel/config.json
  echo "Created /etc/shopss-sentinel/config.json from the example."
else
  echo "Keeping existing /etc/shopss-sentinel/config.json."
fi

chmod 600 /etc/shopss-sentinel/config.json

cat > /usr/local/bin/sentinel <<'EOF'
#!/usr/bin/env bash
cd /opt/shopss-sentinel
exec /usr/bin/python3 -m sentinel.cli "$@"
EOF
chmod 755 /usr/local/bin/sentinel

systemctl daemon-reload
systemctl enable shopss-sentinel
systemctl restart shopss-sentinel

echo
echo "SHOPSS Sentinel v0.4 installed/upgraded and restarted."
echo
echo "Commands:"
echo "  sentinel status"
echo "  sentinel blocks"
echo "  sentinel incidents"
echo "  sentinel unblock <IP>"
echo "  sentinel discord-status"
echo "  sentinel test-discord"
echo "  sentinel website-status"
echo
echo "Service:"
echo "  sudo systemctl status shopss-sentinel --no-pager"
