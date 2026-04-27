# 4) Features

## Networking

- HTTP proxy listener
- SOCKS5 proxy listener
- Host block/bypass rules
- Direct tunnel + relay fallback
- SNI rewrite path for selected domains

## Relay Engine

- Apps Script relay requests
- Optional HTTP/2 multiplexing
- Request batching and coalescing
- Parallel relay strategy across multiple script IDs

## Performance

- Connection pool
- Response cache for static assets
- Parallel and streamed range-download acceleration
- Adaptive direct timeout for repeated failures

## Security

- Local CA certificate generation
- TLS verification controls
- HTTP and SOCKS5 proxy authentication
- Optional privacy telemetry controls

## Observability

- Built-in web dashboard
- JSON admin endpoints
- Prometheus text metrics
- Route decision counters and Telegram-specific counters

