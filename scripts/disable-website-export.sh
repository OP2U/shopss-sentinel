#!/usr/bin/env bash
# Copyright 2026 OP2U
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

CONFIG="/etc/shopss-sentinel/config.json"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this with sudo."
  exit 1
fi

python3 - <<'PY'
import json
from pathlib import Path

path = Path("/etc/shopss-sentinel/config.json")
config = json.loads(path.read_text(encoding="utf-8"))
config["website_export_enabled"] = False

temp = path.with_suffix(".json.tmp")
temp.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
temp.chmod(0o600)
temp.replace(path)
path.chmod(0o600)

print("SHOPSS website export disabled.")
PY

systemctl restart shopss-sentinel
