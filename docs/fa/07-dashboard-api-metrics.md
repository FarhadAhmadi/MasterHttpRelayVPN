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
- نمودار کلاس وضعیت (2xx/3xx/4xx/5xx)
- نمودار صدک‌های latency (از recent events)
- شمارنده رویدادهای self-heal
- کنترل تنظیمات runtime (اعمال زنده + ذخیره در config)

## API

- `GET /api/summary`
- `GET /api/settings`
- `POST /api/settings`
- `POST /api/settings/persist`
- `GET /api/top-hosts?limit=20`
- `GET /api/recent.csv`
- `POST /api/cache/clear`
- `POST /api/route-rules/reload`
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

اگر `admin_token_scopes` تنظیم شود، می‌توانید دسترسی را تفکیک کنید:

- `read`: داشبورد، summary، metrics، CSV، health
- `write`: read + تغییرات runtime (`/api/settings` و reset/cache/rules)
- `admin`: write + ذخیره تنظیمات در فایل (`/api/settings/persist`)
