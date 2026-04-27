# ۱۰) عیب‌یابی

## خطای unauthorized

- `auth_key` با `AUTH_KEY` در `Code.gs` یکی نیست.

## خطای گواهی HTTPS

- `--install-cert` را اجرا کنید.
- مرورگر را کامل ببندید/باز کنید.
- Firefox نیاز به import جداگانه دارد.

## ناپایداری Telegram

- `--telegram-profile` را اجرا کنید.
- اول HTTP proxy را امتحان کنید.
- `telegram_desktop_mode=true` بماند.

## کندی یا timeout

- `python main.py --scan` و جایگزینی `google_ip`
- چند `script_ids` اضافه کنید
- از `/api/summary` و `/metrics` برای تحلیل استفاده کنید

