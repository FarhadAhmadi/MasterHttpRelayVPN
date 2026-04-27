# 2) Installation & Setup

## Requirements

- Python 3.10+
- A Google account (for Apps Script relay)

## Clone

```bash
git clone https://github.com/masterking32/MasterHttpRelayVPN.git
cd MasterHttpRelayVPN
```

## Install dependencies

```bash
pip install -r requirements.txt
```

## Deploy Apps Script (`apps_script/Code.gs`)

1. Open <https://script.google.com> and create a project.
2. Replace default code with `apps_script/Code.gs`.
3. Set your `AUTH_KEY` inside `Code.gs`.
4. Deploy as Web App (Execute as: Me, Access: Anyone).
5. Copy deployment ID.

## Generate config quickly

```bash
python setup.py
```

or copy manually:

```bash
cp config.example.json config.json
```

Set at minimum:

- `script_id` (or `script_ids`)
- `auth_key` (must match `AUTH_KEY` in `Code.gs`)

## Install CA certificate (for HTTPS MITM)

```bash
python main.py --install-cert
```

## Start

```bash
python main.py
```

