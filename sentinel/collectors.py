# Copyright 2026 OP2U
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import subprocess
from pathlib import Path


FAILED_SSH_PATTERNS = (
    "Failed password",
    "Invalid user",
    "authentication failure",
)

NGINX_REQUEST_RE = re.compile(r'"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+([^ ]+)')

SSH_FROM_RE = re.compile(
    r"(?:Failed password for (?:invalid user )?|Invalid user )(?P<user>[^\s]+).*?\bfrom\s+(?P<ip>[0-9a-fA-F:.]+)"
)
SSH_RHOST_RE = re.compile(r"\brhost=(?P<ip>[0-9a-fA-F:.]+)")
SSH_USER_RE = re.compile(r"\buser=(?P<user>[^\s;]+)")


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, check=False)


def _valid_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def parse_ssh_metadata(message: str) -> dict:
    source_ip = None
    username = None

    match = SSH_FROM_RE.search(message)
    if match:
        username = match.group("user")
        source_ip = _valid_ip(match.group("ip"))
    else:
        match = SSH_RHOST_RE.search(message)
        if match:
            source_ip = _valid_ip(match.group("ip"))

        user_match = SSH_USER_RE.search(message)
        if user_match:
            username = user_match.group("user")

    metadata = {}
    if source_ip:
        metadata["source_ip"] = source_ip
    if username:
        metadata["username"] = username

    return metadata


def collect_ssh_failures(cursor: str | None) -> tuple[list[dict], str | None]:
    args = ["journalctl", "-u", "ssh", "--no-pager", "-o", "json"]

    if cursor:
        args.extend(["--after-cursor", cursor])
    else:
        args.append("--since=-2 minutes")

    result = _run(args)

    if result.returncode != 0 and cursor:
        result = _run([
            "journalctl", "-u", "ssh",
            "--since=-2 minutes",
            "--no-pager", "-o", "json"
        ])

    events = []
    last_cursor = cursor

    if result.returncode != 0:
        return events, last_cursor

    for line in result.stdout.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        entry_cursor = entry.get("__CURSOR")
        if entry_cursor:
            last_cursor = str(entry_cursor)

        message = str(entry.get("MESSAGE", ""))
        if any(pattern in message for pattern in FAILED_SSH_PATTERNS):
            events.append({
                "severity": "medium",
                "event_type": "ssh_auth_failure",
                "message": "SSH authentication failure detected.",
                "metadata": parse_ssh_metadata(message),
            })

    return events, last_cursor


def collect_nginx_scanner_hits(
    log_path: Path,
    scanner_paths: list[str],
    offset: int | None
) -> tuple[list[dict], int]:
    if not log_path.exists():
        return [], 0

    try:
        size = log_path.stat().st_size

        if offset is None:
            return [], size

        if offset > size:
            offset = 0

        with log_path.open("r", encoding="utf-8", errors="replace") as f:
            f.seek(offset)
            new_text = f.read()
            new_offset = f.tell()
    except OSError:
        return [], offset or 0

    hits = []
    for line in new_text.splitlines():
        match = NGINX_REQUEST_RE.search(line)
        if not match:
            continue

        request_path = match.group(1).split("?", 1)[0].lower()
        for probe in scanner_paths:
            if request_path.startswith(probe.lower()):
                # Nginx's default combined log starts with the remote address.
                source = line.split(" ", 1)[0].strip()
                metadata = {"path": probe}
                source_ip = _valid_ip(source)
                if source_ip:
                    metadata["source_ip"] = source_ip

                hits.append({
                    "severity": "low",
                    "event_type": "web_probe",
                    "message": f"Common web scanner/probe path requested: {probe}",
                    "metadata": metadata,
                })
                break

    return hits, new_offset


def service_status(service: str) -> bool:
    result = _run(["systemctl", "is-active", "--quiet", service])
    return result.returncode == 0


def public_listening_tcp_ports() -> set[int]:
    result = _run(["ss", "-lntH"])
    ports: set[int] = set()

    if result.returncode != 0:
        return ports

    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue

        local = parts[3]
        try:
            host, raw_port = local.rsplit(":", 1)
            port = int(raw_port)
        except (ValueError, IndexError):
            continue

        host = host.strip("[]")
        if host in {"0.0.0.0", "::", "*"}:
            ports.add(port)

    return ports


def sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None

    digest = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None

    return digest.hexdigest()
