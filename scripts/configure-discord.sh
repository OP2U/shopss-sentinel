#!/usr/bin/env bash
# Copyright 2026 OP2U
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

CONFIG="/etc/shopss-sentinel/config.json"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this with sudo."
  exit 1
fi

if [[ ! -f "${CONFIG}" ]]; then
  echo "Missing ${CONFIG}"
  exit 1
fi

echo "SHOPSS Sentinel - Discord Alert Setup"
echo "====================================="
echo
echo "Create a Discord webhook first, then paste it here."
echo "The webhook will not be echoed to the screen."
echo "Do not paste the webhook into ChatGPT or commit it to GitHub."
echo

read -r -s -p "Discord webhook URL: " WEBHOOK
echo

if [[ -z "${WEBHOOK}" ]]; then
  echo "No webhook entered. Nothing changed."
  exit 1
fi

if [[ "${WEBHOOK}" != https://discord.com/api/webhooks/* && "${WEBHOOK}" != https://discordapp.com/api/webhooks/* ]]; then
  echo "That does not look like a Discord webhook URL. Nothing changed."
  exit 1
fi

export SENTINEL_DISCORD_WEBHOOK="${WEBHOOK}"

python3 - <<'PY'
import json
import os
from pathlib import Path

path = Path("/etc/shopss-sentinel/config.json")
config = json.loads(path.read_text(encoding="utf-8"))

config["discord_alerts_enabled"] = True
config["discord_webhook_url"] = os.environ["SENTINEL_DISCORD_WEBHOOK"]
config["discord_alert_high"] = True
config["discord_alert_block"] = True

temp = path.with_suffix(".json.tmp")
temp.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
temp.chmod(0o600)
temp.replace(path)
path.chmod(0o600)

print("Discord alerts enabled.")
PY

unset SENTINEL_DISCORD_WEBHOOK

systemctl restart shopss-sentinel

echo
echo "Sentinel restarted."
echo "Check: sentinel discord-status"
echo "Test:  sentinel test-discord"
