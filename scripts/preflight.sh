#!/usr/bin/env bash
# Copyright 2026 OP2U
# SPDX-License-Identifier: Apache-2.0
set -u

echo "SHOPSS Sentinel preflight"
echo "========================="
echo

echo "Python:"
python3 --version 2>/dev/null || echo "python3 not found"
echo

echo "Externally-bound TCP listeners:"
ss -lntp 2>/dev/null | sed -n '1,30p'
echo

echo "Relevant services:"
for service in nginx ssh; do
  printf "%-12s " "${service}"
  systemctl is-active "${service}" 2>/dev/null || true
done
echo

echo "Configured integrity targets:"
for path in /etc/ssh/sshd_config /etc/nginx/nginx.conf; do
  if [[ -f "${path}" ]]; then
    echo "FOUND   ${path}"
  else
    echo "MISSING ${path}"
  fi
done
echo

echo "Nginx access log:"
if [[ -f /var/log/nginx/access.log ]]; then
  echo "FOUND   /var/log/nginx/access.log"
else
  echo "MISSING /var/log/nginx/access.log"
fi
