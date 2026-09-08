#!/usr/bin/env bash
# Copyright 2026 OP2U
# SPDX-License-Identifier: Apache-2.0
set -u

echo "SHOPSS Sentinel v0.3 response preflight"
echo "======================================="
echo

echo "UFW:"
ufw status verbose 2>/dev/null || true
echo

echo "Existing nftables rules:"
nft list ruleset 2>/dev/null || true
echo

echo "iptables policies:"
iptables -S 2>/dev/null || true
echo

echo "Current established SSH peer(s):"
cd /opt/shopss-sentinel 2>/dev/null || true
python3 -m sentinel.firewall --peers 2>/dev/null || true
echo

echo "Sentinel response table:"
python3 -m sentinel.firewall --status 2>/dev/null || true
echo

echo "IMPORTANT: v0.3 ships with response_enabled=false."
echo "Installing v0.3 does not create block rules until response is explicitly enabled."
