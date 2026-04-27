# ۹) امنیت و حریم خصوصی

## نکات امنیتی

- `listen_host=127.0.0.1` را نگه دارید مگر نیاز واقعی به LAN.
- در صورت دسترسی دیگران، احراز هویت پروکسی را روشن کنید.
- `admin_host=127.0.0.1` بماند.
- اگر پنل خارج از localhost باز است، `admin_token` تنظیم کنید.
- `ca/ca.key` را هرگز منتشر نکنید.
- `config.json` را commit نکنید.

## حریم خصوصی متریک

- `metrics_redact_query=true`
- `metrics_hash_hosts=true`
- `metrics_include_recent_paths=false`

