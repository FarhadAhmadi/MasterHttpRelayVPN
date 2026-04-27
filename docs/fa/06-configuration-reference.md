# ۶) مرجع تنظیمات

فایل اصلی: `config.json`

## هسته

- `script_id` / `script_ids`
- `auth_key`
- `listen_host`, `listen_port`
- `socks5_enabled`, `socks5_port`
- `verify_ssl`
- `log_level`

## Telegram و احراز هویت

- `telegram_desktop_mode`
- `proxy_auth_enabled`
- `proxy_username`
- `proxy_password`

## ادمین و متریک

- `admin_enabled`, `admin_host`, `admin_port`, `admin_token`
- `metrics_max_recent_events`
- `metrics_bucket_seconds`, `metrics_max_buckets`
- `metrics_redact_query`, `metrics_hash_hosts`, `metrics_include_recent_paths`

## تنظیمات رله

- `relay_timeout`, `tls_connect_timeout`, `tcp_connect_timeout`
- `parallel_relay`
- `max_response_body_bytes`

## دانلود موازی

- `chunked_download_extensions`
- `chunked_download_min_size`
- `chunked_download_chunk_size`
- `chunked_download_max_parallel`
- `chunked_download_max_chunks`

## سیاست‌های مسیر

- `block_hosts`
- `bypass_hosts`
- `hosts`
- `direct_google_exclude`
- `direct_google_allow`
- `youtube_via_relay`

مقادیر پیش‌فرض: [`config.example.json`](../../config.example.json)

