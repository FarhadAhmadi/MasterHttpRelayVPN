# 7) Dashboard, Admin API, and Metrics

Default admin address: `http://127.0.0.1:9090`

## Web Dashboard

- `GET /`

Shows:

- traffic totals
- top hosts
- recent requests
- route decision counters
- live chart
- status-class chart
- latency percentile chart (from recent events)
- self-heal auto-tune event counters
- runtime settings controls (live apply + save to config)
- one-click VPN runtime ON/OFF toggle (service gate)

## API Endpoints

- `GET /api/summary`
- `GET /api/settings`
- `POST /api/settings`
- `POST /api/settings/persist`
- `GET /api/service`
- `POST /api/service`
- `POST /api/quick-action`
- `GET /api/top-hosts?limit=20`
- `GET /api/recent.csv`
- `GET /api/route-rules`
- `POST /api/route-rules`
- `POST /api/route-rules/test`
- `POST /api/cache/clear`
- `POST /api/route-rules/reload`
- `POST /api/reset`
- `GET /api/diagnostics/bundle`
- `GET /healthz`

`/api/service` body example:

```json
{"enabled": false}
```

This does not stop the process; it only pauses/resumes accepting new proxy traffic.

`/api/quick-action` body examples:

```json
{"action":"optimize"}
```

```json
{"action":"probe_relay"}
```

```json
{"action":"panic_off"}
```

`/api/summary` includes:

- telemetry totals and timeseries
- route decision counters
- Telegram route stats
- self-heal event counters
- route rules metadata

## Prometheus

- `GET /metrics`

Includes request counters and route/Telegram route decision counters.

## Persistent JSONL Logs (Optional)

Enable in config:

- `telemetry_jsonl_enabled: true`
- `telemetry_jsonl_path: logs/telemetry.jsonl`
- `telemetry_jsonl_max_bytes`
- `telemetry_jsonl_backups`

This keeps telemetry history across restarts without a database.

## Auth

If `admin_token` is set, include:

```http
X-Admin-Token: your_token
```

If `admin_token_scopes` is set, tokens can be scoped:

- `read`: dashboard, summary, metrics, CSV, health
- `write`: read + runtime mutations (`/api/settings`, `/api/service`, reset/cache/rules actions)
- `admin`: write + persistent config save (`/api/settings/persist`)

CSRF note:

- Browser-originated admin `POST` requests require `X-CSRF-Token` when `admin_csrf_enabled=true`.
- The built-in dashboard sends this header automatically.
