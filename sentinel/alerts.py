# Copyright 2026 OP2U
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import urllib.error
import urllib.request


def send_discord_webhook(webhook_url: str, title: str, description: str, fields: list[dict] | None = None) -> tuple[bool, str]:
    if not webhook_url:
        return False, "Discord webhook URL is empty."

    payload = {
        "username": "SHOPSS Sentinel",
        "embeds": [
            {
                "title": title,
                "description": description,
                "fields": fields or [],
            }
        ],
    }

    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        webhook_url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "SHOPSS-Sentinel/0.4",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            if 200 <= response.status < 300:
                return True, f"Discord webhook delivered ({response.status})."
            return False, f"Discord webhook returned HTTP {response.status}."
    except urllib.error.HTTPError as exc:
        return False, f"Discord webhook returned HTTP {exc.code}."
    except urllib.error.URLError as exc:
        return False, f"Discord webhook connection failed: {exc.reason}"
    except Exception as exc:
        return False, f"Discord webhook error: {exc}"
