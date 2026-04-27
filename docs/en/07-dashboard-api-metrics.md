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

## API Endpoints

- `GET /api/summary`
- `GET /api/top-hosts?limit=20`
- `GET /api/recent.csv`
- `POST /api/reset`
- `GET /healthz`

## Prometheus

- `GET /metrics`

Includes request counters and route/Telegram route decision counters.

## Auth

If `admin_token` is set, include:

```http
X-Admin-Token: your_token
```

