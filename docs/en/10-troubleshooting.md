# 10) Troubleshooting

## unauthorized from relay

- `auth_key` in `config.json` must equal `AUTH_KEY` in `Code.gs`.

## HTTPS certificate errors

- Install CA with `--install-cert`.
- Restart browser fully.
- Import CA in Firefox store separately.

## Telegram unstable

- Use `--telegram-profile`.
- Run `--telegram-diagnose` and follow printed fixes.
- Try profile tuning: `--profile strict_tg` or `--profile balanced`.
- Try HTTP proxy mode in Telegram first.
- Keep `telegram_desktop_mode=true`.
- `--telegram-diagnose` also prints CA/browser trust hints.

## Slow routing or timeouts

- Run `python main.py --scan` and update `google_ip`.
- Add multiple `script_ids`.
- Use dashboard `/api/summary` and `/metrics` to inspect decisions/errors.
