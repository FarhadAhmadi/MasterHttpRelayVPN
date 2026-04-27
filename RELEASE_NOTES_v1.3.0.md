# Release Notes v1.3.0

Release date: 2026-04-27

## Highlights

- Advanced admin panel with richer observability and control surface.
- Runtime settings can now be persisted back to `config.json` from the admin API/UI.
- Scoped admin tokens (`read` / `write` / `admin`) for safer delegated access.

## Admin Panel Upgrades

- New status-class chart (2xx/3xx/4xx/5xx).
- New latency percentile chart (p50/p90/p99 from recent requests).
- Expanded operational actions:
  - Save runtime settings
  - Save runtime settings to disk (`config.json`)
  - Reload route rules
  - Clear cache
  - Reset telemetry
- Better metadata in UI (auth mode, config path, route-rules source).

## Admin API Additions

- `GET /api/settings`
- `POST /api/settings`
- `POST /api/settings/persist`
- `POST /api/cache/clear`
- `POST /api/route-rules/reload`

`/api/summary` now includes a `settings` section for frontend synchronization.

## Security Improvements

- Added optional `admin_token_scopes` config to support per-token scopes:
  - `read` for observability endpoints
  - `write` for runtime mutations
  - `admin` for persistent config write operations
- Legacy `admin_token` remains supported for backward compatibility.

## Configuration

`config.example.json` now includes an `admin_token_scopes` example map.

## Documentation

- Updated EN/FA docs for admin API, configuration, and security guidance.
- Updated all release-note references to v1.3.0.
