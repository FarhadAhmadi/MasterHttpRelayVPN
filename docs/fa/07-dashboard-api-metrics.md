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
- شمارنده رویدادهای self-heal

## API

- `GET /api/summary`
- `GET /api/top-hosts?limit=20`
- `GET /api/recent.csv`
- `POST /api/reset`
- `GET /healthz`

`/api/summary` شامل این بخش‌ها است:

- مجموع تله‌متری و timeseries
- شمارنده تصمیم‌های مسیر
- آمار مسیرهای Telegram
- شمارنده رویدادهای self-heal
- اطلاعات route rules

## Prometheus

- `GET /metrics`

## لاگ JSONL (اختیاری)

در config فعال کنید:

- `telemetry_jsonl_enabled: true`
- `telemetry_jsonl_path: logs/telemetry.jsonl`
- `telemetry_jsonl_max_bytes`
- `telemetry_jsonl_backups`

این قابلیت تاریخچه متریک را بدون دیتابیس نگه می‌دارد.

## احراز هویت ادمین

اگر `admin_token` تنظیم شده باشد، این هدر را بفرستید:

```http
X-Admin-Token: your_token
```
