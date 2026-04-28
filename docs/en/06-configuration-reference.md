# 6) Configuration Reference

Main config file: `config.json`

## Core

- `script_id` / `script_ids`
- `auth_key`
- `listen_host`, `listen_port`
- `socks5_enabled`, `socks5_port`
- `verify_ssl`
- `log_level`

## Telegram and auth

- `telegram_desktop_mode`
- `proxy_auth_enabled`
- `proxy_username`
- `proxy_password`
- `profile` (`strict_tg`, `balanced`, `max_speed`)

## Admin + metrics

- `admin_enabled`, `admin_host`, `admin_port`, `admin_token`
- `admin_token_scopes` (token -> `read` / `write` / `admin`)
- `proxy_service_enabled_on_start` (default ON)
- `admin_auth_window_s`, `admin_auth_max_failures` (auth throttle)
- `admin_force_loopback`, `admin_csrf_enabled`
- `watchdog_enabled`, `watchdog_probe_interval_s`, `watchdog_failure_threshold`
- `metrics_max_recent_events`
- `metrics_bucket_seconds`, `metrics_max_buckets`
- `metrics_redact_query`, `metrics_hash_hosts`, `metrics_include_recent_paths`
- `telemetry_jsonl_enabled`
- `telemetry_jsonl_path`
- `telemetry_jsonl_max_bytes`
- `telemetry_jsonl_backups`

## Relay tuning

- `relay_timeout`, `tls_connect_timeout`, `tcp_connect_timeout`
- `parallel_relay`
- `max_response_body_bytes`

## Download tuning

- `chunked_download_extensions`
- `chunked_download_min_size`
- `chunked_download_chunk_size`
- `chunked_download_max_parallel`
- `chunked_download_max_chunks`

## Routing policies

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

Route rules format:

- `telegram.org -> direct`
- `*.google.com -> direct`
- `* -> relay`

See example: [`route_rules.example.txt`](../../route_rules.example.txt)

See defaults in [`config.example.json`](../../config.example.json).

Example scoped admin tokens:

```json
"admin_token_scopes": {
  "viewer-token": ["read"],
  "operator-token": ["write"],
  "owner-token": ["admin"]
}
```
