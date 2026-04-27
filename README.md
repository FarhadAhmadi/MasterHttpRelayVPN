# MasterHttpRelayVPN (v1)

Domain-fronted local proxy with Apps Script relay, Telegram Desktop compatibility mode, and built-in observability.

## v1 Documentation (Structured)

- **Documentation Hub:** [`docs/README.md`](docs/README.md)
- **English Index:** [`docs/en/INDEX.md`](docs/en/INDEX.md)
- **Farsi Index:** [`docs/fa/INDEX.md`](docs/fa/INDEX.md)
- **Changelog:** [`CHANGELOG.md`](CHANGELOG.md)
- **v1.2.0 Release Notes:** [`RELEASE_NOTES_v1.2.0.md`](RELEASE_NOTES_v1.2.0.md)

## Quick Start

```bash
git clone https://github.com/masterking32/MasterHttpRelayVPN.git
cd MasterHttpRelayVPN
pip install -r requirements.txt
python setup.py
python main.py
```

## Telegram Desktop Quick Setup

```bash
python main.py --telegram-profile
python main.py
```

Then configure Telegram Desktop proxy:

- HTTP: `127.0.0.1:8085` (recommended)
- SOCKS5: `127.0.0.1:1080`

Run quick diagnostics:

```bash
python main.py --telegram-diagnose
```

Switch smart profile:

```bash
python main.py --profile strict_tg
```

## Key v1 Features

- HTTP + SOCKS5 local proxy
- Apps Script relay engine
- Telegram Desktop compatibility mode
- HTTP/SOCKS proxy authentication
- Built-in dashboard + API + Prometheus metrics
- Route decision telemetry and troubleshooting visibility

Optional rule file:

- Copy `route_rules.example.txt` to `route_rules.txt`
- Edit patterns like `telegram.org -> direct` or `*.google.com -> direct`

## Main Files

- `main.py` — startup and CLI
- `setup.py` — interactive config wizard
- `config.example.json` — full config template
- `apps_script/Code.gs` — Google Apps Script relay code
- `src/proxy_server.py` — core proxy + routing logic
- `src/domain_fronter.py` — relay logic
- `src/telemetry.py` — in-memory telemetry

## License

MIT
