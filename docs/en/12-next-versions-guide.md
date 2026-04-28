# 12) Next Versions Guide (10x Plan)

This guide translates the roadmap into implementation-ready steps.

## v1.7 Operations and UX

### 1) System tray controller (Windows)

Goal:
- ON/OFF toggle
- Open dashboard
- Restart relay
- Exit

Recommended stack:
- `pystray` + `Pillow`
- Run tray helper as a separate process that calls admin API (`/api/service`, `/api/quick-action`)

Design notes:
- Keep tray process independent from proxy process.
- If admin API is unavailable, show "Disconnected" state.
- Add retry backoff for status polling.

### 2) Startup service

Use Windows Task Scheduler for user-logon startup.

Included scripts:
- `scripts/windows/install-startup-task.ps1`
- `scripts/windows/uninstall-startup-task.ps1`

Usage:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/windows/install-startup-task.ps1
powershell -ExecutionPolicy Bypass -File scripts/windows/uninstall-startup-task.ps1
```

### 3) Health watchdog

Add watchdog loop in main process:
- checks relay probe every N seconds
- on repeated failure: reconnect fronter pool
- optional process restart if listeners are dead

Suggested config:
- `watchdog_enabled`
- `watchdog_probe_interval_s`
- `watchdog_failure_threshold`

### 4) Kill mode OFF

Current OFF blocks new traffic and closes active sessions.
Enhance with:
- clear DNS override caches
- optional block-listener mode (close HTTP/SOCKS listeners while OFF)

---

## v1.8 Security

### 1) Admin bind hardening

Default:
- `admin_host = 127.0.0.1`

Enhancement:
- Add startup warning if bound to non-loopback
- Optional `admin_force_loopback=true` to refuse non-local binding

### 2) CSRF for admin POST endpoints

Approach:
- Issue session nonce in dashboard HTML boot payload
- Require `X-CSRF-Token` for POSTs
- Verify Origin/Referer as second layer

### 3) Token lifecycle

Add:
- token expiry support
- token rotation endpoint (`admin` scope only)
- emergency one-time token printed to console on startup (optional)

### 4) Audit log

JSONL file:
- action
- actor token id/scope
- source IP
- timestamp
- result

---

## v1.9 Performance

### 1) Adaptive routing

Store rolling host stats:
- p50/p90 latency
- direct success ratio
- relay error ratio

Decision engine:
- prefer direct when stable
- fallback to relay quickly on repeated direct failures

### 2) Connection pooling tuning

Improve:
- per-script-id pool caps
- pool warmup schedule
- stale connection culling

### 3) Cache v2

Add:
- stale-while-revalidate
- stale-if-error
- negative caching for repeat 404/timeout windows

### 4) Warm-up scheduler

Add periodic warm-up requests for active script IDs.

---

## v2.0 Product Features

### 1) Preset profiles

Profiles:
- Gaming
- Telegram
- Streaming
- Max Privacy

Each profile should map to a concrete settings patch.

### 2) Route rules UI

Dashboard page to:
- view/edit rules
- validate syntax
- dry-run host match test
- save + reload

### 3) Backup bundle

Export/import:
- config
- route rules
- profile metadata
- dashboard settings

### 4) Diagnostics bundle

One-click zip:
- redacted config
- recent telemetry CSV
- route decision summary
- latest logs

---

## Observability Add-ons

- live connection table
- alert center (error spikes, relay failures, cache drop)
- daily summary report
- one-click diagnostics collection

---

## Rollout Strategy

1. Ship v1.7 with tray + startup + watchdog.
2. Ship v1.8 with CSRF + token lifecycle + audit log.
3. Ship v1.9 with adaptive routing + cache v2.
4. Freeze APIs, then ship v2.0 product features.

For each release:
- add migration notes
- add defaults in `config.example.json`
- add one troubleshooting section per major feature
