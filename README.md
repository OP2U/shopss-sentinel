# SHOPSS Sentinel

SHOPSS Sentinel is a lightweight Linux security monitoring, detection, and automated-response project built for the SHOPSS infrastructure.

It monitors SSH authentication activity, correlates repeated failures into brute-force detections, checks expected services and public listening ports, watches protected files for integrity changes, stores private event history in SQLite, and can apply temporary SSH-only nftables blocks after safety checks.

**Current release:** v0.5.0

## Highlights

- SSH authentication-failure monitoring from the systemd journal
- Private source-IP and attempted-username metadata
- Brute-force correlation with configurable threshold/window/cooldown
- Temporary SSH-only nftables response with automatic expiry
- Explicit allowlist and active-SSH-session safety checks
- SHA-256 file-integrity baselines
- Expected service and public-port monitoring
- Nginx scanner/probe-path detection
- SQLite event history and incident grouping
- Optional Discord alerts for HIGH detections and automated blocks
- Sanitized website telemetry export with no source identities or raw logs
- Small Python/systemd footprint with no third-party Python packages required

## Security model

Sentinel separates private security data from public portfolio telemetry.

Private data stays in the local SQLite database and can contain source IP addresses, attempted usernames, detailed events, and defensive-action metadata.

The optional website export contains aggregate health/counter fields only. It does **not** include source IPs, attempted usernames, raw SSH/Nginx logs, credentials, internal file paths, Discord webhook URLs, or firewall rules.

## Default detection and response

The default detection rule raises a HIGH brute-force event after **5 SSH failures from the same source within 5 minutes**. A **15-minute alert cooldown** prevents repeated HIGH alerts from the same continuing activity.

Automated response is **disabled by default** in `config.example.json`. When explicitly enabled, the default response threshold is **8 failures from the same source within 5 minutes**, resulting in a **30-minute TCP/22-only block**.

Before a block is applied, Sentinel refuses to block invalid/non-global addresses, configured allowlist entries, or an IP that currently has an established SSH session to the host.

## Requirements

- Ubuntu 24.04 LTS or a comparable systemd-based Linux distribution
- Python 3.12+
- systemd
- nftables for automated response
- Nginx only if using the included web-probe collector/example configuration

Sentinel uses the Python standard library and does not require pip packages.

## Installation

Review the example configuration first:

```bash
cp config.example.json /tmp/sentinel-config-review.json
cat /tmp/sentinel-config-review.json
```

Run the preflight from the project directory:

```bash
sudo bash scripts/preflight.sh
```

Install:

```bash
sudo bash scripts/install.sh
```

Check the service:

```bash
systemctl status shopss-sentinel --no-pager
```

## Operations CLI

```bash
sentinel status
sentinel blocks
sentinel incidents
sentinel incidents --hours 6
sentinel unblock <IP>
sentinel discord-status
sentinel test-discord
sentinel website-status
```

## Optional Discord alerts

Create a Discord webhook in a private/admin channel, then run:

```bash
sudo bash scripts/configure-discord.sh
```

The webhook input is hidden from terminal echo. Do not commit webhook URLs to source control.

Disable and remove the webhook from Sentinel's config with:

```bash
sudo bash scripts/disable-discord.sh
```

## Optional website export

The SHOPSS deployment uses the sanitized export for a live portfolio panel on `shopss.me`.

Enable it with:

```bash
sudo bash scripts/configure-website-export.sh
```

Check it with:

```bash
sentinel website-status
```

For another deployment, change `website_summary_path` in the private config to an appropriate public web-root location.

## Project structure

```text
sentinel/                   Python package
scripts/                    install/configuration/preflight helpers
systemd/                    systemd service
config.example.json         public-safe example configuration
README.md                   project documentation
CHANGELOG.md                release history
SECURITY.md                 security/reporting guidance
LEGAL.md                    legal/use notice
THIRD_PARTY_NOTICES.md      third-party dependency notices
NOTICE                      attribution notice
LICENSE                     Apache License 2.0
.gitignore                  excludes databases, logs, envs, build artifacts
.gitattributes              repository text normalization
```

## Portfolio

Live sanitized project page: https://shopss.me/projects/shopss-sentinel.html

SHOPSS: https://shopss.me

## Important

Sentinel is intended for systems you own or are authorized to administer. Automated response changes firewall state; review the configuration and preflight output before enabling it.

## License and warranty

SHOPSS Sentinel is licensed under the **Apache License 2.0**. It is provided **AS IS**, without warranties; the warranty disclaimer and limitation of liability in the license apply to the extent permitted by law. See `LICENSE`, `NOTICE`, and `LEGAL.md`.

Use Sentinel only on systems you own or are authorized to administer. You are responsible for reviewing automated-response settings and complying with applicable law and third-party terms.
