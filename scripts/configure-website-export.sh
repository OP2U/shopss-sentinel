#!/usr/bin/env bash
# Copyright 2026 OP2U
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

CONFIG="/etc/shopss-sentinel/config.json"
SITE_ROOT="/var/www/shopss"
EXPORT_DIR="${SITE_ROOT}/data"
EXPORT_FILE="${EXPORT_DIR}/sentinel-summary.json"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this with sudo."
  exit 1
fi

if [[ ! -f "${CONFIG}" ]]; then
  echo "Missing ${CONFIG}"
  exit 1
fi

if [[ ! -d "${SITE_ROOT}" ]]; then
  echo "SHOPSS site root not found: ${SITE_ROOT}"
  echo "Nothing changed."
  exit 1
fi

mkdir -p "${EXPORT_DIR}"
chmod 755 "${EXPORT_DIR}"

# Protect the live generated file from accidental Git commits.
if [[ ! -f "${EXPORT_DIR}/.gitignore" ]]; then
  printf "sentinel-summary.json\n" > "${EXPORT_DIR}/.gitignore"
fi

python3 - <<'PY'
import json
from pathlib import Path

path = Path("/etc/shopss-sentinel/config.json")
config = json.loads(path.read_text(encoding="utf-8"))

config["website_export_enabled"] = True
config["website_summary_path"] = "/var/www/shopss/data/sentinel-summary.json"

temp = path.with_suffix(".json.tmp")
temp.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
temp.chmod(0o600)
temp.replace(path)
path.chmod(0o600)

print("SHOPSS website export enabled.")
PY

systemctl restart shopss-sentinel

echo
echo "Sentinel restarted."
echo "Waiting for the first website export..."
sleep 3

if [[ -f "${EXPORT_FILE}" ]]; then
  chmod 644 "${EXPORT_FILE}"
  echo "Created: ${EXPORT_FILE}"
else
  echo "Export has not appeared yet. It should be created on Sentinel's next cycle."
fi

echo
echo "Check with:"
echo "  sentinel website-status"
echo "  cat ${EXPORT_FILE}"
