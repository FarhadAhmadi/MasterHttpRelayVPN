#!/usr/bin/env python3
"""Interactive setup wizard for MasterHttpRelayVPN.

Writes a ready-to-use config.json by prompting only for the values
the user really has to choose. Everything else gets a sane default.

Run:
    python setup.py
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import string
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG_PATH = HERE / "config.json"
EXAMPLE_PATH = HERE / "config.example.json"


def _c(code: str, text: str) -> str:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def bold(t: str) -> str: return _c("1", t)
def cyan(t: str) -> str: return _c("36", t)
def green(t: str) -> str: return _c("32", t)
def yellow(t: str) -> str: return _c("33", t)
def red(t: str) -> str: return _c("31", t)
def dim(t: str) -> str: return _c("2", t)


def prompt(question: str, default: str | None = None) -> str:
    suffix = f" [{dim(default)}]" if default else ""
    while True:
        try:
            raw = input(f"{cyan('?')} {question}{suffix}: ").strip()
        except EOFError:
            print()
            sys.exit(1)
        if not raw and default is not None:
            return default
        if raw:
            return raw
        print(red("  value required"))


def prompt_yes_no(question: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        raw = input(f"{cyan('?')} {question} [{hint}]: ").strip().lower()
        if not raw:
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False


def prompt_choice(question: str, choices: list[str], default: str) -> str:
    options = "/".join(choices)
    while True:
        raw = input(f"{cyan('?')} {question} [{options}] [{dim(default)}]: ").strip()
        if not raw:
            return default
        if raw in choices:
            return raw
        print(red(f"  choose one of: {options}"))


def random_auth_key(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def apply_telegram_quick_profile(cfg: dict) -> dict:
    """Apply a secure local-only profile tuned for Telegram Desktop."""
    cfg["listen_host"] = "127.0.0.1"
    cfg["listen_port"] = int(cfg.get("listen_port", 8085) or 8085)
    cfg["socks5_enabled"] = True
    cfg["socks5_port"] = int(cfg.get("socks5_port", 1080) or 1080)
    cfg["telegram_desktop_mode"] = True
    cfg["profile"] = "balanced"
    cfg["lan_sharing"] = False
    cfg["proxy_auth_enabled"] = False
    cfg["proxy_username"] = ""
    cfg["proxy_password"] = ""
    cfg["admin_enabled"] = True
    cfg["admin_host"] = "127.0.0.1"
    cfg["admin_port"] = int(cfg.get("admin_port", 9090) or 9090)
    cfg["metrics_redact_query"] = True
    cfg["metrics_hash_hosts"] = False
    cfg["metrics_include_recent_paths"] = False
    cfg["metrics_bucket_seconds"] = 30
    cfg["metrics_max_buckets"] = 240
    cfg["metrics_max_recent_events"] = 4000
    cfg["telemetry_jsonl_enabled"] = False
    cfg["telemetry_jsonl_path"] = "logs/telemetry.jsonl"
    cfg["telemetry_jsonl_max_bytes"] = 5 * 1024 * 1024
    cfg["telemetry_jsonl_backups"] = 3
    cfg["route_rules_file"] = "route_rules.txt"
    cfg["self_heal_enabled"] = True
    cfg["self_heal_window_s"] = 120
    cfg["self_heal_error_threshold"] = 5
    return cfg


def load_base_config() -> dict:
    if EXAMPLE_PATH.exists():
        try:
            with EXAMPLE_PATH.open() as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "mode": "apps_script",
        "google_ip": "216.239.38.120",
        "front_domain": "www.google.com",
        "listen_host": "127.0.0.1",
        "listen_port": 8085,
        "socks5_enabled": True,
        "socks5_port": 1080,
        "profile": "balanced",
        "proxy_auth_enabled": False,
        "proxy_username": "",
        "proxy_password": "",
        "telegram_desktop_mode": True,
        "log_level": "INFO",
        "verify_ssl": True,
        "lan_sharing": False,
        "relay_timeout": 25,
        "tls_connect_timeout": 15,
        "tcp_connect_timeout": 10,
        "max_response_body_bytes": 200 * 1024 * 1024,
        "chunked_download_min_size": 5 * 1024 * 1024,
        "chunked_download_chunk_size": 512 * 1024,
        "chunked_download_max_parallel": 8,
        "chunked_download_max_chunks": 256,
        "telemetry_jsonl_enabled": False,
        "telemetry_jsonl_path": "logs/telemetry.jsonl",
        "telemetry_jsonl_max_bytes": 5 * 1024 * 1024,
        "telemetry_jsonl_backups": 3,
        "route_rules_file": "route_rules.txt",
        "self_heal_enabled": True,
        "self_heal_window_s": 120,
        "self_heal_error_threshold": 5,
        "hosts": {},
    }


def configure_apps_script(cfg: dict) -> dict:
    print()
    print(bold("Google Apps Script setup"))
    print(dim("  1. Open https://script.google.com -> New project"))
    print(dim("  2. Paste apps_script/Code.gs from this repo into the editor"))
    print(dim("  3. Set AUTH_KEY in Code.gs to the password below"))
    print(dim("  4. Deploy -> New deployment -> Web app"))
    print(dim("     Execute as: Me   |   Who has access: Anyone"))
    print(dim("  5. Copy the Deployment ID and paste it here"))
    print()

    ids_raw = prompt(
        "Deployment ID(s) - comma-separated for load balancing",
        default=None,
    )
    ids = [x.strip() for x in ids_raw.split(",") if x.strip()]
    if len(ids) == 1:
        cfg["script_id"] = ids[0]
        cfg.pop("script_ids", None)
    else:
        cfg["script_ids"] = ids
        cfg.pop("script_id", None)
    return cfg


def configure_network(cfg: dict) -> dict:
    print()
    print(bold("Network settings") + dim("  (press enter to accept defaults)"))
    cfg["lan_sharing"] = prompt_yes_no(
        "Enable LAN sharing?",
        default=bool(cfg.get("lan_sharing", False)),
    )

    default_host = str(cfg.get("listen_host", "127.0.0.1"))
    if cfg["lan_sharing"] and default_host == "127.0.0.1":
        default_host = "0.0.0.0"
    cfg["listen_host"] = prompt("Listen host", default=default_host)

    port = prompt("HTTP proxy port", default=str(cfg.get("listen_port", 8085)))
    try:
        cfg["listen_port"] = int(port)
    except ValueError:
        cfg["listen_port"] = 8085

    socks5 = prompt_yes_no("Enable SOCKS5 proxy?", default=bool(cfg.get("socks5_enabled", True)))
    cfg["socks5_enabled"] = socks5
    if socks5:
        sport = prompt("SOCKS5 port", default=str(cfg.get("socks5_port", 1080)))
        try:
            cfg["socks5_port"] = int(sport)
        except ValueError:
            cfg["socks5_port"] = 1080
    cfg["telegram_desktop_mode"] = prompt_yes_no(
        "Enable Telegram Desktop compatibility mode?",
        default=bool(cfg.get("telegram_desktop_mode", True)),
    )

    proxy_auth = prompt_yes_no(
        "Enable proxy authentication (HTTP + SOCKS5)?",
        default=bool(cfg.get("proxy_auth_enabled", False)),
    )
    cfg["proxy_auth_enabled"] = proxy_auth
    if proxy_auth:
        cfg["proxy_username"] = prompt(
            "Proxy username",
            default=str(cfg.get("proxy_username", "user")),
        )
        cfg["proxy_password"] = prompt(
            "Proxy password",
            default=str(cfg.get("proxy_password", random_auth_key(16))),
        )
    else:
        cfg["proxy_username"] = ""
        cfg["proxy_password"] = ""

    print()
    print(bold("Admin dashboard and metrics"))
    admin_enabled = prompt_yes_no(
        "Enable local admin dashboard/API on localhost?",
        default=bool(cfg.get("admin_enabled", True)),
    )
    cfg["admin_enabled"] = admin_enabled
    if admin_enabled:
        aport = prompt("Admin port", default=str(cfg.get("admin_port", 9090)))
        try:
            cfg["admin_port"] = int(aport)
        except ValueError:
            cfg["admin_port"] = 9090
        cfg["admin_host"] = cfg.get("admin_host", "127.0.0.1")
        cfg["metrics_redact_query"] = prompt_yes_no(
            "Redact query strings in metrics?",
            default=bool(cfg.get("metrics_redact_query", True)),
        )
        cfg["metrics_hash_hosts"] = prompt_yes_no(
            "Hash host names in metrics (privacy mode)?",
            default=bool(cfg.get("metrics_hash_hosts", False)),
        )
        cfg["metrics_include_recent_paths"] = prompt_yes_no(
            "Include paths in recent request list?",
            default=bool(cfg.get("metrics_include_recent_paths", False)),
        )
        cfg["metrics_max_recent_events"] = int(cfg.get("metrics_max_recent_events", 2000))
        cfg["metrics_bucket_seconds"] = int(cfg.get("metrics_bucket_seconds", 60))
        cfg["metrics_max_buckets"] = int(cfg.get("metrics_max_buckets", 180))
    else:
        cfg["admin_enabled"] = False
    cfg["profile"] = prompt_choice(
        "Runtime profile",
        ["strict_tg", "balanced", "max_speed"],
        default=str(cfg.get("profile", "balanced")),
    )
    return cfg


def write_config(cfg: dict) -> None:
    if CONFIG_PATH.exists():
        backup = CONFIG_PATH.with_suffix(".json.bak")
        shutil.copy2(CONFIG_PATH, backup)
        print(yellow(f"  existing config.json backed up to {backup.name}"))
    with CONFIG_PATH.open("w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")


def main() -> int:
    print()
    print(bold("MasterHttpRelayVPN - setup wizard"))
    print(dim("Answer a few questions and we'll write config.json for you."))

    if CONFIG_PATH.exists():
        if not prompt_yes_no("config.json already exists. Overwrite?", default=False):
            print(dim("Nothing changed."))
            return 0

    cfg = load_base_config()
    cfg["mode"] = "apps_script"

    if prompt_yes_no("Apply Telegram quick profile defaults?", default=True):
        cfg = apply_telegram_quick_profile(cfg)
        print(green("  Telegram quick profile applied (you can still change values below)."))

    suggested_key = random_auth_key()
    print()
    print(bold("Shared password (auth_key)"))
    print(dim("  Must match AUTH_KEY inside apps_script/Code.gs."))
    cfg["auth_key"] = prompt("auth_key", default=suggested_key)

    cfg = configure_apps_script(cfg)
    cfg = configure_network(cfg)

    write_config(cfg)

    print()
    print(green(f"[OK] wrote {CONFIG_PATH.name}"))
    print()
    print(bold("Next step:"))
    print(f"  python main.py")
    print()
    print(yellow("Reminder: the AUTH_KEY inside apps_script/Code.gs must match the auth_key"))
    print(yellow("you just entered - otherwise the relay will return 'unauthorized'."))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        print(dim("Cancelled."))
        sys.exit(130)
