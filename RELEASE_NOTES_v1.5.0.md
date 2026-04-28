# Release Notes v1.5.0

## Dashboard and UX

- Added one-click action bar in admin panel:
  - One-click optimize
  - Relay probe
  - Panic OFF
- Added runtime cards for:
  - Service state (ON/OFF)
  - Active sessions

## VPN ON/OFF Reliability

- Turning VPN OFF now cancels active proxy sessions immediately.
- OFF mode still keeps admin dashboard/API available for easy recovery.

## New Admin API

- `POST /api/quick-action`
  - `{ "action": "optimize" }`
  - `{ "action": "probe_relay" }`
  - `{ "action": "panic_off" }`

## Version

- Core version bumped to `1.5.0`.
