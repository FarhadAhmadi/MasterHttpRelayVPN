# 3) Telegram Desktop Guide

This project includes Telegram-focused behavior in v1.

## Fastest Setup (Recommended)

Run:

```bash
python main.py --telegram-profile
```

This writes Telegram-optimized defaults to `config.json`, including local-only binding and proxy auth.

Then start:

```bash
python main.py
```

## Telegram Desktop Proxy Settings

Preferred:

- Type: HTTP
- Host: `127.0.0.1`
- Port: `8085`

Alternative:

- Type: SOCKS5
- Host: `127.0.0.1`
- Port: `1080`

If proxy auth is enabled, use `proxy_username` + `proxy_password` from `config.json`.

## Telegram Mode Behavior

- `telegram_desktop_mode=true` enables fail-fast behavior for SOCKS IP-literal dead paths.
- Helps Telegram rotate data centers faster on blocked routes.
- Adaptive timeout and failure TTL logic reduce repeated stalls.

