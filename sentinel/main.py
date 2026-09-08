# Copyright 2026 OP2U
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import argparse
import json
import signal
import sqlite3
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .alerts import send_discord_webhook
from .collectors import (
    collect_nginx_scanner_hits,
    collect_ssh_failures,
    public_listening_tcp_ports,
    service_status,
    sha256_file,
)
from .config import load_config
from .firewall import temporary_block_ssh
from .storage import Storage


RUNNING = True


def stop_handler(signum, frame):
    global RUNNING
    RUNNING = False


def write_public_summary(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    temp.replace(path)


def write_website_summary(path: Path, payload: dict) -> None:
    # This file is intentionally public. The payload is constructed only
    # from aggregate/sanitized fields and never contains private metadata.
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o755)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temp.chmod(0o644)
    temp.replace(path)
    path.chmod(0o644)


def add_structured_event(storage: Storage, event: dict) -> None:
    metadata = event.get("metadata") or {}
    storage.add_event(
        event["severity"],
        event["event_type"],
        event["message"],
        json.dumps(metadata, separators=(",", ":")) if metadata else None,
    )


def dedupe_event(storage: Storage, key: str, value: str, severity: str, event_type: str, message: str) -> None:
    previous = storage.get_state(key)
    if previous != value:
        storage.set_state(key, value)
        storage.add_event(severity, event_type, message)


def source_counts(storage: Storage, event_type: str, window_minutes: int) -> Counter:
    since = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
    rows = storage.recent_events(since, event_type)

    counts = Counter()

    for row in rows:
        metadata_json = row[5]
        if not metadata_json:
            continue

        try:
            metadata = json.loads(metadata_json)
        except json.JSONDecodeError:
            continue

        source_ip = metadata.get("source_ip")
        if source_ip:
            counts[source_ip] += 1

    return counts


def deliver_high_alert(config, source_ip: str, count: int) -> None:
    if not (config.discord_alerts_enabled and config.discord_alert_high):
        return

    send_discord_webhook(
        config.discord_webhook_url,
        "HIGH — SSH brute-force detected",
        "SHOPSS Sentinel correlated repeated SSH authentication failures.",
        [
            {"name": "Source", "value": source_ip, "inline": True},
            {"name": "Failures", "value": str(count), "inline": True},
            {"name": "Window", "value": f"{config.ssh_bruteforce_window_minutes} minutes", "inline": True},
        ],
    )


def deliver_block_alert(config, source_ip: str, count: int) -> None:
    if not (config.discord_alerts_enabled and config.discord_alert_block):
        return

    send_discord_webhook(
        config.discord_webhook_url,
        "SSH source temporarily blocked",
        "SHOPSS Sentinel applied an automated SSH-only response.",
        [
            {"name": "Source", "value": source_ip, "inline": True},
            {"name": "Failures", "value": str(count), "inline": True},
            {"name": "Block", "value": f"{config.response_ssh_block_minutes} minutes", "inline": True},
        ],
    )


def correlate_ssh_bruteforce(storage: Storage, config) -> None:
    now = datetime.now(timezone.utc)
    counts = source_counts(
        storage,
        "ssh_auth_failure",
        config.ssh_bruteforce_window_minutes,
    )

    for source_ip, count in counts.items():
        if count < config.ssh_bruteforce_threshold:
            continue

        state_key = f"ssh_bruteforce:last_alert:{source_ip}"
        previous_raw = storage.get_state(state_key)

        if previous_raw:
            try:
                previous = datetime.fromisoformat(previous_raw)
                if previous.tzinfo is None:
                    previous = previous.replace(tzinfo=timezone.utc)

                if now - previous < timedelta(minutes=config.ssh_bruteforce_cooldown_minutes):
                    continue
            except ValueError:
                pass

        storage.set_state(state_key, now.isoformat())
        storage.add_event(
            "high",
            "ssh_bruteforce",
            f"SSH brute-force threshold reached ({count} events/{config.ssh_bruteforce_window_minutes}m).",
            json.dumps(
                {
                    "source_ip": source_ip,
                    "event_count": count,
                    "window_minutes": config.ssh_bruteforce_window_minutes,
                    "cooldown_minutes": config.ssh_bruteforce_cooldown_minutes,
                },
                separators=(",", ":"),
            ),
        )

        deliver_high_alert(config, source_ip, count)


def respond_to_ssh_bruteforce(storage: Storage, config) -> None:
    if not config.response_enabled:
        return

    now = datetime.now(timezone.utc)
    counts = source_counts(
        storage,
        "ssh_auth_failure",
        config.response_ssh_block_window_minutes,
    )

    for source_ip, count in counts.items():
        if count < config.response_ssh_block_threshold:
            continue

        state_key = f"ssh_response:last_block:{source_ip}"
        previous_raw = storage.get_state(state_key)

        if previous_raw:
            try:
                previous = datetime.fromisoformat(previous_raw)
                if previous.tzinfo is None:
                    previous = previous.replace(tzinfo=timezone.utc)

                if now - previous < timedelta(minutes=config.response_ssh_block_minutes):
                    continue
            except ValueError:
                pass

        result = temporary_block_ssh(
            source_ip,
            config.response_ssh_block_minutes,
            config.response_allowlist_ips,
        )

        metadata = {
            "source_ip": source_ip,
            "event_count": count,
            "block_minutes": config.response_ssh_block_minutes,
            "result": "blocked" if result.ok else "skipped",
            "detail": result.message,
        }

        if result.ok:
            storage.set_state(state_key, now.isoformat())
            storage.add_event(
                "info",
                "ssh_block",
                f"Temporary SSH block applied for {config.response_ssh_block_minutes} minutes.",
                json.dumps(metadata, separators=(",", ":")),
            )

            deliver_block_alert(config, source_ip, count)
        else:
            skip_key = f"ssh_response:last_skip:{source_ip}:{result.message}"
            if storage.get_state(skip_key) != now.strftime("%Y-%m-%dT%H"):
                storage.set_state(skip_key, now.strftime("%Y-%m-%dT%H"))
                storage.add_event(
                    "info",
                    "ssh_block_skipped",
                    "Automated SSH block was skipped by a safety check.",
                    json.dumps(metadata, separators=(",", ":")),
                )


def distinct_ssh_sources_24h(db_path: Path, since_iso: str) -> int:
    con = sqlite3.connect(db_path)
    rows = con.execute(
        """
        SELECT metadata_json
        FROM events
        WHERE created_at >= ?
          AND event_type = 'ssh_auth_failure'
          AND metadata_json IS NOT NULL
        """,
        (since_iso,),
    ).fetchall()
    con.close()

    sources = set()

    for (metadata_json,) in rows:
        try:
            metadata = json.loads(metadata_json)
        except (TypeError, json.JSONDecodeError):
            continue

        source = metadata.get("source_ip")
        if source:
            sources.add(source)

    return len(sources)


def run_cycle(config, storage: Storage) -> None:
    journal_cursor = storage.get_state("ssh:journal_cursor")
    ssh_events, new_cursor = collect_ssh_failures(journal_cursor)

    for event in ssh_events:
        add_structured_event(storage, event)

    if new_cursor and new_cursor != journal_cursor:
        storage.set_state("ssh:journal_cursor", new_cursor)

    correlate_ssh_bruteforce(storage, config)
    respond_to_ssh_bruteforce(storage, config)

    raw_offset = storage.get_state("nginx:access_offset")
    nginx_offset = int(raw_offset) if raw_offset is not None else None

    nginx_events, new_offset = collect_nginx_scanner_hits(
        config.nginx_access_log,
        config.scanner_paths,
        nginx_offset,
    )

    for event in nginx_events:
        add_structured_event(storage, event)

    storage.set_state("nginx:access_offset", str(new_offset))

    services = {}

    for service in config.expected_services:
        active = service_status(service)
        services[service] = active

        dedupe_event(
            storage,
            f"service:{service}",
            "up" if active else "down",
            "info" if active else "high",
            "service_state",
            f"Expected service '{service}' is {'active' if active else 'not active'}."
        )

    current_ports = public_listening_tcp_ports()
    expected_ports = set(config.expected_tcp_ports)

    missing_ports = sorted(expected_ports - current_ports)
    unexpected_ports = sorted(current_ports - expected_ports)

    dedupe_event(
        storage,
        "ports:missing",
        ",".join(map(str, missing_ports)),
        "high" if missing_ports else "info",
        "port_baseline",
        "Expected public listening TCP port baseline changed."
    )

    dedupe_event(
        storage,
        "ports:unexpected",
        ",".join(map(str, unexpected_ports)),
        "medium" if unexpected_ports else "info",
        "port_baseline",
        "Unexpected public listening TCP port baseline changed."
    )

    integrity_ok = True

    for path in config.integrity_files:
        digest = sha256_file(path)
        baseline_key = f"hash:baseline:{path}"
        observed_key = f"hash:observed:{path}"
        baseline = storage.get_state(baseline_key)

        if digest is None:
            integrity_ok = False
            dedupe_event(
                storage,
                observed_key,
                "unavailable",
                "high",
                "file_integrity",
                f"Integrity target unavailable: {path}"
            )
            continue

        if baseline is None:
            storage.set_state(baseline_key, digest)
            storage.set_state(observed_key, digest)
            storage.add_event("info", "file_integrity", f"Integrity baseline created for {path}")
            continue

        if digest != baseline:
            integrity_ok = False
            dedupe_event(
                storage,
                observed_key,
                digest,
                "high",
                "file_integrity",
                f"Protected file changed from its trusted baseline: {path}"
            )
        else:
            dedupe_event(
                storage,
                observed_key,
                digest,
                "info",
                "file_integrity",
                f"Protected file returned to its trusted baseline: {path}"
            )

    since_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

    severity_counts = {
        severity: storage.count_events_since(since_24h, severity=severity)
        for severity in ("low", "medium", "high", "critical")
    }

    security_events_24h = sum(severity_counts.values())
    ssh_blocks_24h = storage.count_events_since(since_24h, "ssh_block")
    ssh_sources_24h = distinct_ssh_sources_24h(config.database_path, since_24h)

    host_healthy = (
        all(services.values() or [True])
        and not missing_ports
        and not unexpected_ports
        and integrity_ok
    )

    if severity_counts["critical"] > 0 or ssh_blocks_24h > 0 or severity_counts["high"] > 0:
        threat_activity = "elevated"
    elif security_events_24h > 0:
        threat_activity = "active"
    else:
        threat_activity = "quiet"

    public_summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "secure" if host_healthy else "attention",
        "host_health": "healthy" if host_healthy else "attention",
        "threat_activity": threat_activity,
        "services": {
            "healthy": sum(1 for value in services.values() if value),
            "total": len(services),
        },
        "security_events_24h": security_events_24h,
        "severity_24h": severity_counts,
        "ssh_failures_24h": storage.count_events_since(since_24h, "ssh_auth_failure"),
        "ssh_sources_24h": ssh_sources_24h,
        "ssh_bruteforce_alerts_24h": storage.count_events_since(since_24h, "ssh_bruteforce"),
        "ssh_blocks_24h": ssh_blocks_24h,
        "web_probes_24h": storage.count_events_since(since_24h, "web_probe"),
        "integrity": "ok" if integrity_ok else "changed",
        "port_baseline": "ok" if not missing_ports and not unexpected_ports else "changed",
        "response_mode": "enabled" if config.response_enabled else "observe",
    }

    write_public_summary(config.public_summary_path, public_summary)

    if config.website_export_enabled:
        write_website_summary(config.website_summary_path, public_summary)


def main() -> None:
    parser = argparse.ArgumentParser(description="SHOPSS Sentinel")
    parser.add_argument(
        "--config",
        default="/etc/shopss-sentinel/config.json",
        help="Path to config JSON"
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one collection cycle and exit"
    )
    args = parser.parse_args()

    config = load_config(args.config)
    storage = Storage(config.database_path)

    if args.once:
        run_cycle(config, storage)
        return

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)

    while RUNNING:
        run_cycle(config, storage)

        for _ in range(max(1, config.poll_interval_seconds)):
            if not RUNNING:
                break
            time.sleep(1)


if __name__ == "__main__":
    main()
