# Copyright 2026 OP2U
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Config:
    poll_interval_seconds: int
    database_path: Path
    public_summary_path: Path
    expected_services: list[str]
    expected_tcp_ports: list[int]
    integrity_files: list[Path]
    nginx_access_log: Path
    scanner_paths: list[str]

    ssh_bruteforce_threshold: int
    ssh_bruteforce_window_minutes: int
    ssh_bruteforce_cooldown_minutes: int

    response_enabled: bool
    response_ssh_block_threshold: int
    response_ssh_block_window_minutes: int
    response_ssh_block_minutes: int
    response_allowlist_ips: list[str]

    discord_alerts_enabled: bool
    discord_webhook_url: str
    discord_alert_high: bool
    discord_alert_block: bool

    website_export_enabled: bool
    website_summary_path: Path

    event_retention_days: int


def load_config(path: str | Path) -> Config:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))

    return Config(
        poll_interval_seconds=int(raw.get("poll_interval_seconds", 60)),
        database_path=Path(raw.get("database_path", "/var/lib/shopss-sentinel/sentinel.db")),
        public_summary_path=Path(raw.get("public_summary_path", "/var/lib/shopss-sentinel/public-summary.json")),
        expected_services=list(raw.get("expected_services", [])),
        expected_tcp_ports=[int(p) for p in raw.get("expected_tcp_ports", [])],
        integrity_files=[Path(p) for p in raw.get("integrity_files", [])],
        nginx_access_log=Path(raw.get("nginx_access_log", "/var/log/nginx/access.log")),
        scanner_paths=list(raw.get("scanner_paths", [])),

        ssh_bruteforce_threshold=max(1, int(raw.get("ssh_bruteforce_threshold", 5))),
        ssh_bruteforce_window_minutes=max(1, int(raw.get("ssh_bruteforce_window_minutes", 5))),
        ssh_bruteforce_cooldown_minutes=max(1, int(raw.get("ssh_bruteforce_cooldown_minutes", 15))),

        response_enabled=bool(raw.get("response_enabled", False)),
        response_ssh_block_threshold=max(1, int(raw.get("response_ssh_block_threshold", 8))),
        response_ssh_block_window_minutes=max(1, int(raw.get("response_ssh_block_window_minutes", 5))),
        response_ssh_block_minutes=max(1, int(raw.get("response_ssh_block_minutes", 30))),
        response_allowlist_ips=[str(x) for x in raw.get("response_allowlist_ips", [])],

        discord_alerts_enabled=bool(raw.get("discord_alerts_enabled", False)),
        discord_webhook_url=str(raw.get("discord_webhook_url", "")),
        discord_alert_high=bool(raw.get("discord_alert_high", True)),
        discord_alert_block=bool(raw.get("discord_alert_block", True)),

        website_export_enabled=bool(raw.get("website_export_enabled", False)),
        website_summary_path=Path(raw.get("website_summary_path", "/var/www/shopss/data/sentinel-summary.json")),

        event_retention_days=max(1, int(raw.get("event_retention_days", 30))),
    )
