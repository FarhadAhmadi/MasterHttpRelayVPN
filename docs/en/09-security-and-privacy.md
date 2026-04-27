# 9) Security & Privacy

## Security Best Practices

- Keep `listen_host=127.0.0.1` unless LAN access is required.
- Enable proxy auth if proxy can be reached by others.
- Keep `admin_host=127.0.0.1`.
- Set `admin_token` if admin is exposed beyond localhost.
- Prefer `admin_token_scopes` to separate viewer/operator/admin tokens.
- Do not share `ca/ca.key`.
- Do not commit `config.json`.

## Privacy Controls

- `metrics_redact_query=true`
- `metrics_hash_hosts=true`
- `metrics_include_recent_paths=false`
