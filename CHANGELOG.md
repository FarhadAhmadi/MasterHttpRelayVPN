# Changelog

All notable changes to this project are documented in this file.

The format is inspired by Keep a Changelog and Semantic Versioning.

## [1.2.0] - 2026-04-27

### Added

- New CLI diagnostics command: `--telegram-diagnose`.
- Smart runtime profiles: `--profile strict_tg|balanced|max_speed`.
- Route rules file support via `route_rules_file` and sample `route_rules.example.txt`.
- Optional persistent telemetry logging in JSONL format with rotation:
  - `telemetry_jsonl_enabled`
  - `telemetry_jsonl_path`
  - `telemetry_jsonl_max_bytes`
  - `telemetry_jsonl_backups`
- CA/browser trust guidance helper used by diagnose flow.
- Route decision and Telegram decision counters in `/api/summary` and `/metrics`.

### Changed

- Version bumped to `1.2.0`.
- Telegram profile defaults keep `proxy_auth_enabled=false` (safe/easy first-run).
- Telegram mode routing improved:
  - Telegram-domain direct preference with relay fallback.
  - SOCKS IP-literal fail-fast to speed DC rotation.
- Adaptive direct timeout and adaptive failure cooldown TTL.
- Self-healing runtime behavior for repeated relay errors.
- Dashboard now surfaces route decisions and self-heal signals.
- Structured v1 documentation expanded and synchronized (EN + FA).

### Docs

- Full structured docs under `docs/` with English and Farsi indices.
- Command/config/features/troubleshooting/roadmap docs updated for v1.2.0 capabilities.

### Notes

- Telegram connectivity depends on local network conditions and Apps Script health.
- For fastest setup: run `python main.py --telegram-profile` then `python main.py`.

## [1.1.0] - Previous

- Baseline v1 feature set prior to 1.2.0 improvements.

