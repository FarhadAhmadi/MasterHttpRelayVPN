# Release Notes v1.8.0

## Step 3: Route Rules UI + Diagnostics Bundle

### Route Rules Editor

- Added dashboard-based route rules editor.
- Load current rules from file, edit inline, and save safely.
- Validation prevents bad syntax and invalid actions.
- Added host test endpoint to preview matched action.

New API:
- `GET /api/route-rules`
- `POST /api/route-rules` (`{ "text": "..." }`)
- `POST /api/route-rules/test` (`{ "host": "api.telegram.org" }`)

### Diagnostics Bundle

- Added one-click diagnostics bundle download from dashboard.
- Exports ZIP with:
  - `summary.json`
  - `settings.json`
  - `route_rules.txt`
  - `recent.csv`

New API:
- `GET /api/diagnostics/bundle`

## Version

- Core version bumped to `1.8.0`.
