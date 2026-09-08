# Security Policy

## Sensitive data

Do not commit or publish:

- `/etc/shopss-sentinel/config.json`
- Discord webhook URLs
- response allowlist IPs from a real deployment
- Sentinel SQLite databases
- raw SSH/Nginx logs
- generated live telemetry from a production host
- credentials, tokens, private keys, or server secrets

Use `config.example.json` for public configuration examples.

## Automated response

Automated blocking is disabled in the example configuration. Review firewall state and active SSH peers before enabling response on a production server.

The response engine is designed to create temporary SSH-only blocks in the dedicated `inet shopss_sentinel` nftables table. Operators should still maintain independent backups and out-of-band recovery access for production systems.

## Reporting a vulnerability

If you find a security issue in SHOPSS Sentinel, please report it privately to the repository owner rather than posting sensitive exploit details in a public issue.
