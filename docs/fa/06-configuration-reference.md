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
- `profile` (`strict_tg`, `balanced`, `max_speed`)

## ادمین و متریک

- `admin_enabled`, `admin_host`, `admin_port`, `admin_token`
- `metrics_max_recent_events`
- `metrics_bucket_seconds`, `metrics_max_buckets`
- `metrics_redact_query`, `metrics_hash_hosts`, `metrics_include_recent_paths`
- `telemetry_jsonl_enabled`
- `telemetry_jsonl_path`
- `telemetry_jsonl_max_bytes`
- `telemetry_jsonl_backups`

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
- `route_rules_file`
- `self_heal_enabled`
- `self_heal_window_s`
- `self_heal_error_threshold`

فرمت route rules:

- `telegram.org -> direct`
- `*.google.com -> direct`
- `* -> relay`

نمونه فایل: [`route_rules.example.txt`](../../route_rules.example.txt)

مقادیر پیش‌فرض: [`config.example.json`](../../config.example.json)
