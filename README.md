# SHOPSS Sentinel v0.6.1

Reporting & Metrics maintenance release.

## v0.6.1 fix

v0.6.0 contained an indentation error in the new event-retention method. The v0.6 CLI
could still read the previously generated summary, making new v0.6 metrics appear as zero
even though the collector was no longer updating that summary.

v0.6.1 fixes the retention method and restores normal collector cycles.

`sentinel status` now also displays the summary generation timestamp so stale telemetry is
easier to spot.

## v0.6 reporting

The primary metrics are:

- SSH attempts / 24h
- unique SSH sources / 24h
- distinct brute-force sources / 24h
- distinct sources blocked / 24h
- active SSH blocks
- SSH attempts / 1h
- unique SSH sources / 1h
- web probes / 1h

Threat Activity represents the current 15-minute window.

Automatic event retention defaults to 30 days.

No detection thresholds, allowlists, Discord settings, or firewall behavior changed.


## Public repository safety

This repository contains source code and example configuration only.

Do **not** commit:

- `/etc/shopss-sentinel/config.json`
- Discord webhook URLs
- admin allowlist IPs
- production SQLite databases
- generated Sentinel summaries
- private event history
- VPS credentials or SSH keys

## License and warranty

SHOPSS Sentinel is licensed under the **Apache License 2.0**.

It is provided **AS IS**, without warranties. The warranty disclaimer and limitation of
liability in the license apply to the extent permitted by law. See `LICENSE`, `NOTICE`,
`LEGAL.md`, and `THIRD_PARTY_NOTICES.md`.

Use Sentinel only on systems you own or are authorized to administer.
