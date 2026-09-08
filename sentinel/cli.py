# Copyright 2026 OP2U
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import argparse
import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .alerts import send_discord_webhook
from .config import load_config
from .firewall import list_active_blocks, unblock_ssh


DEFAULT_CONFIG = "/etc/shopss-sentinel/config.json"



def _fmt_expiry(block: dict) -> str:
    text = block.get("expires_text")
    if text:
        return text

    seconds = block.get("expires_seconds")
    if seconds is None:
        return "unknown"

    seconds = max(0, int(seconds))
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)

    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if seconds or not parts:
        parts.append(f"{seconds}s")

    return "".join(parts)

def command_status(config_path: str):
    cfg = load_config(config_path)

    if not cfg.public_summary_path.exists():
        print("No public summary exists yet.")
        return 1

    summary = json.loads(cfg.public_summary_path.read_text(encoding="utf-8"))
    severity = summary.get("severity_24h", {})
    services = summary.get("services", {})

    print()
    print("SHOPSS SENTINEL")
    print("=" * 56)
    print(f"Host health       : {summary.get('host_health', summary.get('status', 'unknown')).upper()}")
    print(f"Threat activity   : {summary.get('threat_activity', 'unknown').upper()}")
    print(f"Response mode     : {summary.get('response_mode', 'unknown').upper()}")
    print(f"Services          : {services.get('healthy', 0)}/{services.get('total', 0)} healthy")
    print(f"File integrity    : {summary.get('integrity', 'unknown').upper()}")
    print(f"Port baseline     : {summary.get('port_baseline', 'unknown').upper()}")
    print()
    print("LAST 24 HOURS")
    print("-" * 56)
    print(f"Security events   : {summary.get('security_events_24h', 0)}")
    print(f"SSH failures      : {summary.get('ssh_failures_24h', 0)}")
    print(f"SSH sources       : {summary.get('ssh_sources_24h', 0)}")
    print(f"Brute-force alerts: {summary.get('ssh_bruteforce_alerts_24h', 0)}")
    print(f"SSH blocks        : {summary.get('ssh_blocks_24h', 0)}")
    print(f"Web probes        : {summary.get('web_probes_24h', 0)}")
    print()
    print("SEVERITY")
    print("-" * 56)
    print(f"Low               : {severity.get('low', 0)}")
    print(f"Medium            : {severity.get('medium', 0)}")
    print(f"High              : {severity.get('high', 0)}")
    print(f"Critical          : {severity.get('critical', 0)}")
    print()

    return 0


def command_blocks():
    blocks = list_active_blocks()

    print()
    print("SHOPSS SENTINEL - ACTIVE SSH BLOCKS")
    print("=" * 72)

    if not blocks:
        print("No active SSH blocks.")
        print()
        return 0

    for block in blocks:
        print(
            f"{block['ip']:40} {block['family']:5} "
            f"expires={_fmt_expiry(block)}"
        )

    print()
    return 0


def command_unblock(ip: str):
    result = unblock_ssh(ip)

    if result.ok:
        print(result.message)
        return 0

    print(f"ERROR: {result.message}")
    return 1


def command_incidents(config_path: str, hours: int):
    cfg = load_config(config_path)
    db_path = cfg.database_path

    if not db_path.exists():
        print("Sentinel database does not exist.")
        return 1

    since = (datetime.now(timezone.utc) - timedelta(hours=max(1, hours))).isoformat()
    con = sqlite3.connect(db_path)

    rows = con.execute(
        """
        SELECT created_at, event_type, metadata_json
        FROM events
        WHERE created_at >= ?
          AND event_type IN ('ssh_auth_failure','ssh_bruteforce','ssh_block')
        ORDER BY created_at ASC
        """,
        (since,),
    ).fetchall()

    incidents = defaultdict(lambda: {
        "failures": 0,
        "alerts": 0,
        "blocks": 0,
        "first": None,
        "last": None,
        "users": set(),
    })

    for created_at, event_type, metadata_json in rows:
        if not metadata_json:
            continue

        try:
            meta = json.loads(metadata_json)
        except json.JSONDecodeError:
            continue

        source = meta.get("source_ip")
        if not source:
            continue

        item = incidents[source]

        if item["first"] is None:
            item["first"] = created_at
        item["last"] = created_at

        if event_type == "ssh_auth_failure":
            item["failures"] += 1
            if meta.get("username"):
                item["users"].add(meta["username"])
        elif event_type == "ssh_bruteforce":
            item["alerts"] += 1
        elif event_type == "ssh_block":
            item["blocks"] += 1

    print()
    print(f"SHOPSS SENTINEL - SSH INCIDENTS ({hours}H)")
    print("=" * 112)

    if not incidents:
        print("No SSH incidents with source metadata.")
        print()
        con.close()
        return 0

    ordered = sorted(
        incidents.items(),
        key=lambda pair: (pair[1]["failures"], pair[1]["blocks"]),
        reverse=True,
    )

    for source, item in ordered:
        users = ",".join(sorted(item["users"])) if item["users"] else "-"
        print(
            f"{source:40} failures={item['failures']:3} "
            f"alerts={item['alerts']:2} blocks={item['blocks']:2} users={users}"
        )

    print()
    con.close()
    return 0



def command_discord_status(config_path: str):
    cfg = load_config(config_path)

    print()
    print("SHOPSS SENTINEL - DISCORD ALERTS")
    print("=" * 56)
    print(f"Enabled           : {'YES' if cfg.discord_alerts_enabled else 'NO'}")
    print(f"Webhook configured: {'YES' if bool(cfg.discord_webhook_url) else 'NO'}")
    print(f"HIGH alerts       : {'YES' if cfg.discord_alert_high else 'NO'}")
    print(f"Block alerts      : {'YES' if cfg.discord_alert_block else 'NO'}")
    print()

    return 0


def command_test_discord(config_path: str):
    cfg = load_config(config_path)

    if not cfg.discord_webhook_url:
        print("ERROR: Discord webhook URL is not configured.")
        return 1

    ok, message = send_discord_webhook(
        cfg.discord_webhook_url,
        "SHOPSS Sentinel test",
        "Discord alert delivery is working.",
        [
            {"name": "Host health", "value": "TEST", "inline": True},
            {"name": "Response", "value": "TEST ONLY", "inline": True},
        ],
    )

    if ok:
        print("Discord test alert sent successfully.")
        return 0

    print(f"ERROR: {message}")
    return 1



def command_website_status(config_path: str):
    cfg = load_config(config_path)

    print()
    print("SHOPSS SENTINEL - WEBSITE EXPORT")
    print("=" * 60)
    print(f"Enabled           : {'YES' if cfg.website_export_enabled else 'NO'}")
    print(f"Export path       : {cfg.website_summary_path}")
    print(f"Export exists     : {'YES' if cfg.website_summary_path.exists() else 'NO'}")

    if cfg.website_summary_path.exists():
        try:
            payload = json.loads(cfg.website_summary_path.read_text(encoding="utf-8"))
            print(f"Generated at      : {payload.get('generated_at', 'unknown')}")
            print(f"Host health       : {str(payload.get('host_health', 'unknown')).upper()}")
            print(f"Threat activity   : {str(payload.get('threat_activity', 'unknown')).upper()}")
        except Exception:
            print("Export readable   : NO")
        else:
            print("Export readable   : YES")

    print()
    return 0


def main():
    parser = argparse.ArgumentParser(prog="sentinel", description="SHOPSS Sentinel CLI")
    parser.add_argument("--config", default=DEFAULT_CONFIG)

    subs = parser.add_subparsers(dest="command", required=True)

    subs.add_parser("status", help="Show Sentinel health and 24-hour security summary")
    subs.add_parser("blocks", help="Show active temporary SSH blocks")

    unblock = subs.add_parser("unblock", help="Manually remove a temporary SSH block")
    unblock.add_argument("ip")

    incidents = subs.add_parser("incidents", help="Group recent SSH activity by source")
    incidents.add_argument("--hours", type=int, default=24)

    subs.add_parser("discord-status", help="Show Discord alert configuration without revealing the webhook")
    subs.add_parser("test-discord", help="Send a safe Discord test alert")
    subs.add_parser("website-status", help="Show sanitized website-export status")

    args = parser.parse_args()

    if args.command == "status":
        raise SystemExit(command_status(args.config))
    if args.command == "blocks":
        raise SystemExit(command_blocks())
    if args.command == "unblock":
        raise SystemExit(command_unblock(args.ip))
    if args.command == "incidents":
        raise SystemExit(command_incidents(args.config, args.hours))
    if args.command == "discord-status":
        raise SystemExit(command_discord_status(args.config))
    if args.command == "test-discord":
        raise SystemExit(command_test_discord(args.config))
    if args.command == "website-status":
        raise SystemExit(command_website_status(args.config))


if __name__ == "__main__":
    main()
