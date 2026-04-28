# Release Notes v1.6.0

## Performance

- Upgraded response cache eviction to true LRU behavior.
- Cache hits now refresh entry priority, keeping hot assets available longer.
- Cache variants are separated by `Accept-Encoding` to avoid content mismatch.

## Security

- Added admin auth brute-force protection with per-IP rate limiting.
- After too many failed token attempts, admin API returns `429 Too Many Requests`.
- Successful admin auth clears the failure bucket for that IP.

## Reliability

- Existing VPN ON/OFF flow remains immediate and keeps dashboard available.
- Runtime settings now expose admin auth throttle values for easier tuning.

## Version

- Core version bumped to `1.6.0`.
