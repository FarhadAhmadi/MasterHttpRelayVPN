# Release Notes v1.4.0

## New

- Web admin now includes a one-click **VPN ON/OFF** control.
- New runtime API for service state:
  - `GET /api/service`
  - `POST /api/service` with `{ "enabled": true|false }`
- Added helper batch files:
  - `vpn-dashboard.bat`
  - `vpn-on.bat`
  - `vpn-off.bat`

## Improved

- Turning VPN OFF now immediately cancels active proxy sessions.
- Dashboard now shows:
  - active sessions
  - service state (ON/OFF)

## Notes

- OFF mode keeps admin dashboard/API running, while blocking proxy traffic.
- Use admin panel at `http://127.0.0.1:9090`.
