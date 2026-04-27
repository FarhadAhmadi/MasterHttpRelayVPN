# ۷) داشبورد، API ادمین و متریک‌ها

آدرس پیش‌فرض ادمین: `http://127.0.0.1:9090`

## داشبورد وب

- `GET /`

نمایش:

- مجموع ترافیک
- top hosts
- recent requests
- route decisions
- نمودار زنده

## API

- `GET /api/summary`
- `GET /api/top-hosts?limit=20`
- `GET /api/recent.csv`
- `POST /api/reset`
- `GET /healthz`

## Prometheus

- `GET /metrics`

## احراز هویت ادمین

اگر `admin_token` تنظیم شده باشد، این هدر را بفرستید:

```http
X-Admin-Token: your_token
```

