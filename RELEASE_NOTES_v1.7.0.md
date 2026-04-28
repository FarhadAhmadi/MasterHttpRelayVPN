# Release Notes v1.7.0

## Step 2: Watchdog + Admin Hardening

### Watchdog

- Added background relay watchdog loop.
- Probes relay health at configurable intervals.
- On repeated failures, it recycles relay connections automatically.

New config keys:
- `watchdog_enabled` (default `true`)
- `watchdog_probe_interval_s` (default `30`)
- `watchdog_failure_threshold` (default `4`)

### Admin security

- Added optional loopback enforcement for admin dashboard binding.
- Startup warns when admin is bound to non-loopback interfaces.
- Added CSRF protection for browser-originated admin POST requests.
- Added stronger brute-force controls from previous release.

New config keys:
- `admin_force_loopback` (default `false`)
- `admin_csrf_enabled` (default `true`)
- `admin_auth_window_s`
- `admin_auth_max_failures`

## Version

- Core version bumped to `1.7.0`.
