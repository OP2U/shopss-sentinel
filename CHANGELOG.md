# Changelog

## Public packaging / licensing

- Switched the public source distribution to Apache License 2.0.
- Added NOTICE, LEGAL.md, and THIRD_PARTY_NOTICES.md.
- Added SPDX Apache-2.0 identifiers to source and scripts.
- Clarified authorized-use, warranty, liability, and third-party dependency notices.

## 0.5.0

- Added sanitized live website export for `shopss.me`.
- Added `website_export_enabled`.
- Added `website_summary_path`.
- Added `sentinel website-status`.
- Added `scripts/configure-website-export.sh`.
- Added `scripts/disable-website-export.sh`.
- Public website export is mode 0644 and contains aggregate fields only.
- Private database/event metadata remains outside the website root.
- Existing detection, response, Discord, and operations behavior is unchanged.

## 0.4.2

- Added safe Discord configuration and test tooling.

## 0.4.1

- Fixed active-block expiry display.

## 0.4.0

- Added operations CLI and incident grouping.

## 0.3.0

- Added automated SSH response.

## 0.2.x

- Added source parsing, correlation, and cooldown.

## 0.1.0

- Initial monitoring release.
