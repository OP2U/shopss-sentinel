# Copyright 2026 OP2U
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass


TABLE_FAMILY = "inet"
TABLE_NAME = "shopss_sentinel"
SET_V4 = "ssh_block_v4"
SET_V6 = "ssh_block_v6"


@dataclass
class FirewallResult:
    ok: bool
    message: str


def _run(args: list[str], input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        input=input_text,
        capture_output=True,
        text=True,
        check=False,
    )


def nft_available() -> bool:
    return _run(["nft", "--version"]).returncode == 0


def table_exists() -> bool:
    return _run(["nft", "list", "table", TABLE_FAMILY, TABLE_NAME]).returncode == 0


def ensure_firewall_table() -> FirewallResult:
    if not nft_available():
        return FirewallResult(False, "nft command is not available.")

    if table_exists():
        return FirewallResult(True, "SHOPSS Sentinel nftables table already exists.")

    ruleset = f"""
table {TABLE_FAMILY} {TABLE_NAME} {{
    set {SET_V4} {{
        type ipv4_addr
        flags timeout
    }}

    set {SET_V6} {{
        type ipv6_addr
        flags timeout
    }}

    chain input {{
        type filter hook input priority -10; policy accept;

        tcp dport 22 ip saddr @{SET_V4} drop
        tcp dport 22 ip6 saddr @{SET_V6} drop
    }}
}}
"""

    result = _run(["nft", "-f", "-"], input_text=ruleset)
    if result.returncode != 0:
        return FirewallResult(False, result.stderr.strip() or "Unable to create Sentinel nftables table.")

    return FirewallResult(True, "Created dedicated SHOPSS Sentinel nftables table.")


def active_ssh_peer_ips() -> set[str]:
    result = _run(["ss", "-tnH"])
    peers: set[str] = set()

    if result.returncode != 0:
        return peers

    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue

        local = parts[3]
        peer = parts[4]

        try:
            _local_host, local_port = local.rsplit(":", 1)
            peer_host, _peer_port = peer.rsplit(":", 1)
        except ValueError:
            continue

        if local_port != "22":
            continue

        peer_host = peer_host.strip("[]")
        try:
            peers.add(str(ipaddress.ip_address(peer_host)))
        except ValueError:
            continue

    return peers


def safe_to_block(source_ip: str, allowlist_ips: list[str]) -> tuple[bool, str]:
    try:
        ip = ipaddress.ip_address(source_ip)
    except ValueError:
        return False, "Source is not a valid IP address."

    if not ip.is_global:
        return False, "Source is not a globally-routable address."

    normalized_allowlist = set()
    for value in allowlist_ips:
        try:
            normalized_allowlist.add(str(ipaddress.ip_address(value)))
        except ValueError:
            continue

    if str(ip) in normalized_allowlist:
        return False, "Source is explicitly allowlisted."

    if str(ip) in active_ssh_peer_ips():
        return False, "Source currently has an established SSH connection."

    return True, "Source passed response safety checks."


def temporary_block_ssh(source_ip: str, minutes: int, allowlist_ips: list[str]) -> FirewallResult:
    allowed, reason = safe_to_block(source_ip, allowlist_ips)
    if not allowed:
        return FirewallResult(False, reason)

    setup = ensure_firewall_table()
    if not setup.ok:
        return setup

    ip = ipaddress.ip_address(source_ip)
    set_name = SET_V4 if ip.version == 4 else SET_V6

    script = (
        f"add element {TABLE_FAMILY} {TABLE_NAME} {set_name} "
        f"{{ {ip} timeout {max(1, int(minutes))}m }}\n"
    )

    result = _run(["nft", "-f", "-"], input_text=script)

    if result.returncode != 0:
        stderr = result.stderr.strip()
        if "File exists" in stderr:
            return FirewallResult(True, "SSH source is already temporarily blocked.")
        return FirewallResult(False, stderr or "Unable to add temporary SSH block.")

    return FirewallResult(True, f"Temporarily blocked source from TCP/22 for {minutes} minutes.")


def unblock_ssh(source_ip: str) -> FirewallResult:
    try:
        ip = ipaddress.ip_address(source_ip)
    except ValueError:
        return FirewallResult(False, "Invalid IP address.")

    if not table_exists():
        return FirewallResult(False, "SHOPSS Sentinel firewall table does not exist.")

    set_name = SET_V4 if ip.version == 4 else SET_V6
    script = f"delete element {TABLE_FAMILY} {TABLE_NAME} {set_name} {{ {ip} }}\n"

    result = _run(["nft", "-f", "-"], input_text=script)

    if result.returncode != 0:
        return FirewallResult(False, result.stderr.strip() or "Unable to remove SSH block.")

    return FirewallResult(True, f"Removed temporary SSH block for {ip}.")



def _parse_duration_seconds(value: str | None) -> int | None:
    if not value:
        return None

    total = 0
    matched = False

    for amount, unit in re.findall(r"(\\d+)([dhms])", value):
        matched = True
        number = int(amount)

        if unit == "d":
            total += number * 86400
        elif unit == "h":
            total += number * 3600
        elif unit == "m":
            total += number * 60
        elif unit == "s":
            total += number

    return total if matched else None


def _list_set_blocks(set_name: str, family_label: str) -> list[dict]:
    result = _run(["nft", "list", "set", TABLE_FAMILY, TABLE_NAME, set_name])

    if result.returncode != 0:
        return []

    match = re.search(r"elements\\s*=\\s*\\{(.*?)\\}", result.stdout, re.DOTALL)
    if not match:
        return []

    body = match.group(1)
    blocks = []

    for raw_element in body.split(","):
        element = raw_element.strip()
        if not element:
            continue

        ip_match = re.match(r"([^\\s]+)", element)
        if not ip_match:
            continue

        ip_text = ip_match.group(1)

        try:
            ip_text = str(ipaddress.ip_address(ip_text))
        except ValueError:
            continue

        expires_match = re.search(r"\\bexpires\\s+([0-9dhms]+)", element)
        timeout_match = re.search(r"\\btimeout\\s+([0-9dhms]+)", element)

        expires_text = expires_match.group(1) if expires_match else None
        timeout_text = timeout_match.group(1) if timeout_match else None
        expires_seconds = _parse_duration_seconds(expires_text)

        # An element at zero is no longer an active block even if nft's
        # garbage collector has not removed its storage yet.
        if expires_seconds is not None and expires_seconds <= 0:
            continue

        blocks.append({
            "ip": ip_text,
            "family": family_label,
            "expires_text": expires_text,
            "timeout_text": timeout_text,
            "expires_seconds": expires_seconds,
        })

    return blocks


def list_active_blocks() -> list[dict]:
    if not table_exists():
        return []

    blocks = []
    blocks.extend(_list_set_blocks(SET_V4, "IPv4"))
    blocks.extend(_list_set_blocks(SET_V6, "IPv6"))
    return blocks

def table_status() -> str:
    result = _run(["nft", "list", "table", TABLE_FAMILY, TABLE_NAME])
    if result.returncode != 0:
        return "SHOPSS Sentinel nftables table is not currently installed."
    return result.stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="SHOPSS Sentinel nftables helper")
    parser.add_argument("--status", action="store_true", help="Show Sentinel firewall table")
    parser.add_argument("--peers", action="store_true", help="Show established SSH peer IPs")
    args = parser.parse_args()

    if args.peers:
        print("Established SSH peer IPs:")
        peers = sorted(active_ssh_peer_ips())
        if not peers:
            print("  (none detected)")
        else:
            for peer in peers:
                print(f"  {peer}")
        return

    print(table_status())


if __name__ == "__main__":
    main()
