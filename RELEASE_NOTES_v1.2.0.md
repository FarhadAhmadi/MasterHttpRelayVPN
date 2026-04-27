# Release v1.2.0 - Telegram Reliability + v1 Docs Upgrade

## Highlights

This release focuses on practical Telegram Desktop reliability, better runtime tuning, and publish-ready project documentation.

### Telegram + Connectivity

- Added `--telegram-diagnose` for one-command local diagnostics.
- Added smart tuning profiles:
  - `--profile strict_tg`
  - `--profile balanced`
  - `--profile max_speed`
- Improved Telegram routing behavior in Telegram mode:
  - direct-preferred for Telegram domains,
  - fail-fast for SOCKS IP-literal dead paths (faster DC rotation).

### Runtime Resilience

- Added self-healing behavior:
  - detects repeated relay errors,
  - lowers pressure automatically,
  - quarantines repeatedly failing targets for cooldown.
- Added adaptive timeout/TTL strategy for repeated failures.

### Observability

- Added optional persistent telemetry JSONL logs with rotation.
- `/api/summary` now includes route decisions, Telegram stats, self-heal events, route-rules metadata.
- `/metrics` includes route decision counters and Telegram route decision counters.

### Routing Rules

- Added human-readable route rules file support (`route_rules_file`).
- Added sample file: `route_rules.example.txt`.

### Security / Trust UX

- Diagnose flow now prints CA trust/browser hints with actionable fixes.

### Documentation

- Structured and publish-ready docs set in `docs/` (EN + FA).
- Root README files streamlined and linked to docs index.

---

## Upgrade Notes

1. Pull latest changes.
2. Review `config.example.json` for new keys.
3. (Optional) copy `route_rules.example.txt` -> `route_rules.txt` and customize.
4. Run Telegram quick setup:
   - `python main.py --telegram-profile`
5. Run diagnostics:
   - `python main.py --telegram-diagnose`
6. Start proxy:
   - `python main.py`

---

## Quick Start for Telegram Desktop

1. `python main.py --telegram-profile`
2. `python main.py --profile strict_tg` (optional)
3. `python main.py`
4. In Telegram Desktop:
   - HTTP proxy: `127.0.0.1:8085` (recommended)
   - SOCKS5 proxy: `127.0.0.1:1080` (alternative)

---

## Known Limitations

- Telegram MTProto behavior over heavily blocked IP paths can still vary by ISP/network.
- Apps Script quota or deployment misconfiguration can impact relay reliability.

