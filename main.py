#!/usr/bin/env python3
"""
DomainFront Tunnel — Bypass DPI censorship via Google Apps Script.

Run a local HTTP proxy that tunnels all traffic through a Google Apps
Script relay fronted by www.google.com (TLS SNI shows www.google.com
while the encrypted Host header points at script.google.com).
"""

import argparse
import asyncio
import json
import logging
import os
import socket
import ssl
import time
import sys

# Project modules live under ./src — put that folder on sys.path so the
# historical flat imports ("from proxy_server import …") keep working.
_SRC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from cert_installer import ca_trust_hints, install_ca, is_ca_trusted
from constants import __version__
from lan_utils import log_lan_access
from google_ip_scanner import scan_sync
from logging_utils import configure as configure_logging, print_banner
from mitm import CA_CERT_FILE
from domain_fronter import DomainFronter
from proxy_server import ProxyServer


def setup_logging(level_name: str):
    configure_logging(level_name)


_PLACEHOLDER_AUTH_KEYS = {
    "",
    "CHANGE_ME_TO_A_STRONG_SECRET",
    "your-secret-password-here",
}


def parse_args():
    parser = argparse.ArgumentParser(
        prog="domainfront-tunnel",
        description="Local HTTP proxy that relays traffic through Google Apps Script.",
    )
    parser.add_argument(
        "-c", "--config",
        default=os.environ.get("DFT_CONFIG", "config.json"),
        help="Path to config file (default: config.json, env: DFT_CONFIG)",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=None,
        help="Override listen port (env: DFT_PORT)",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Override listen host (env: DFT_HOST)",
    )
    parser.add_argument(
        "--socks5-port",
        type=int,
        default=None,
        help="Override SOCKS5 listen port (env: DFT_SOCKS5_PORT)",
    )
    parser.add_argument(
        "--disable-socks5",
        action="store_true",
        help="Disable the built-in SOCKS5 listener.",
    )
    parser.add_argument(
        "--admin-port",
        type=int,
        default=None,
        help="Override admin dashboard/API port (env: DFT_ADMIN_PORT).",
    )
    parser.add_argument(
        "--disable-admin",
        action="store_true",
        help="Disable the built-in admin dashboard/API listener.",
    )
    parser.add_argument(
        "--telegram-desktop-mode",
        action="store_true",
        help="Enable Telegram Desktop compatibility mode for SOCKS IP-literal handling.",
    )
    parser.add_argument(
        "--telegram-profile",
        action="store_true",
        help="Apply recommended Telegram Desktop settings to config and exit.",
    )
    parser.add_argument(
        "--telegram-diagnose",
        action="store_true",
        help="Run Telegram connectivity diagnostics and print actionable hints.",
    )
    parser.add_argument(
        "--profile",
        choices=["strict_tg", "balanced", "max_speed"],
        default=None,
        help="Apply a smart runtime profile and save it to config.",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Override log level (env: DFT_LOG_LEVEL)",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--install-cert",
        action="store_true",
        help="Install the MITM CA certificate as a trusted root and exit.",
    )
    parser.add_argument(
        "--no-cert-check",
        action="store_true",
        help="Skip the certificate installation check on startup.",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Scan Google IPs to find the fastest reachable one and exit.",
    )
    return parser.parse_args()


def _apply_telegram_profile(config: dict) -> dict:
    """Apply a practical local-only Telegram profile.

    Returns updated config.
    """
    config["listen_host"] = "127.0.0.1"
    config["listen_port"] = int(config.get("listen_port", 8085) or 8085)
    config["socks5_enabled"] = True
    config["socks5_port"] = int(config.get("socks5_port", 1080) or 1080)
    config["telegram_desktop_mode"] = True
    config["lan_sharing"] = False
    config["admin_enabled"] = True
    config["admin_host"] = "127.0.0.1"
    config["admin_port"] = int(config.get("admin_port", 9090) or 9090)

    # Telemetry defaults: safe-by-default with useful debugging.
    config["metrics_redact_query"] = True
    config["metrics_hash_hosts"] = False
    config["metrics_include_recent_paths"] = False
    config["metrics_bucket_seconds"] = 30
    config["metrics_max_buckets"] = 240
    config["metrics_max_recent_events"] = 4000

    config["proxy_auth_enabled"] = False
    config["proxy_username"] = ""
    config["proxy_password"] = ""
    return config


def _apply_runtime_profile(config: dict, profile: str) -> dict:
    out = dict(config)
    out["profile"] = profile
    if profile == "strict_tg":
        out["telegram_desktop_mode"] = True
        out["relay_timeout"] = 22
        out["tls_connect_timeout"] = 10
        out["tcp_connect_timeout"] = 6
        out["chunked_download_max_parallel"] = 4
        out["parallel_relay"] = 1
        out["self_heal_enabled"] = True
    elif profile == "balanced":
        out["telegram_desktop_mode"] = True
        out["relay_timeout"] = 25
        out["tls_connect_timeout"] = 15
        out["tcp_connect_timeout"] = 10
        out["chunked_download_max_parallel"] = 8
        out["parallel_relay"] = max(1, int(out.get("parallel_relay", 1)))
        out["self_heal_enabled"] = True
    elif profile == "max_speed":
        out["telegram_desktop_mode"] = True
        out["relay_timeout"] = 30
        out["tls_connect_timeout"] = 15
        out["tcp_connect_timeout"] = 8
        out["chunked_download_max_parallel"] = 12
        out["parallel_relay"] = max(2, int(out.get("parallel_relay", 2)))
        out["self_heal_enabled"] = True
    return out


def _check_port_bind(host: str, port: int) -> tuple[bool, str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        return False, str(exc)
    try:
        sock.bind((host, int(port)))
        return True, "free"
    except OSError as exc:
        return False, str(exc)
    finally:
        sock.close()


def _probe_live_http_proxy(host: str, port: int,
                           auth_enabled: bool) -> tuple[bool, str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        return False, f"{type(exc).__name__}: {exc}"
    sock.settimeout(2.0)
    try:
        sock.connect((host, int(port)))
        req = (
            "GET http://example.com/ HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        sock.sendall(req)
        data = sock.recv(512)
        if not data:
            return False, "no response"
        if b"407 Proxy Authentication Required" in data:
            return auth_enabled, "proxy requires auth (expected)"
        if b"HTTP/" in data:
            return True, "proxy responded"
        return False, "unexpected reply"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        sock.close()


def _probe_live_socks5(host: str, port: int,
                       auth_enabled: bool) -> tuple[bool, str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        return False, f"{type(exc).__name__}: {exc}"
    sock.settimeout(2.0)
    try:
        sock.connect((host, int(port)))
        if auth_enabled:
            sock.sendall(b"\x05\x01\x02")
            reply = sock.recv(2)
            if reply == b"\x05\x02":
                return True, "auth method required (expected)"
            return False, f"unexpected method reply: {reply!r}"
        sock.sendall(b"\x05\x01\x00")
        reply = sock.recv(2)
        if reply == b"\x05\x00":
            return True, "no-auth method accepted"
        return False, f"unexpected method reply: {reply!r}"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        sock.close()


async def _probe_front_connect(front_domain: str, connect_ip: str,
                               timeout: float) -> tuple[bool, str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        t0 = time.perf_counter()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                connect_ip, 443, ssl=ctx, server_hostname=front_domain
            ),
            timeout=timeout,
        )
        writer.write(
            f"HEAD / HTTP/1.1\r\nHost: {front_domain}\r\nConnection: close\r\n\r\n".encode()
        )
        await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        ms = int((time.perf_counter() - t0) * 1000)
        if data.startswith(b"HTTP/"):
            return True, f"ok ({ms}ms)"
        return False, f"non-http reply ({ms}ms)"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


async def _probe_relay_latency(config: dict) -> tuple[bool, str]:
    fronter = DomainFronter(config)
    t0 = time.perf_counter()
    try:
        raw = await asyncio.wait_for(
            fronter.relay("HEAD", "http://example.com/", {}, b""),
            timeout=float(config.get("relay_timeout", 25)),
        )
        status, _, _ = fronter._split_raw_response(raw)
        ms = int((time.perf_counter() - t0) * 1000)
        if 200 <= status < 500:
            return True, f"status={status} ({ms}ms)"
        return False, f"status={status} ({ms}ms)"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        try:
            await fronter.close()
        except Exception:
            pass


def _run_telegram_diagnose(config: dict) -> int:
    print("Telegram Diagnose")
    print("=================")
    issues = 0

    host = str(config.get("listen_host", "127.0.0.1"))
    http_port = int(config.get("listen_port", 8085))
    socks_host = str(config.get("socks5_host", host))
    socks_port = int(config.get("socks5_port", 1080))

    ok_http_bind, http_bind_msg = _check_port_bind(host, http_port)
    ok_socks_bind, socks_bind_msg = _check_port_bind(socks_host, socks_port)
    print(
        f"[HTTP port bind]  {host}:{http_port} -> "
        f"{'OK' if ok_http_bind else 'FAIL'} ({http_bind_msg})"
    )
    print(
        f"[SOCKS port bind] {socks_host}:{socks_port} -> "
        f"{'OK' if ok_socks_bind else 'FAIL'} ({socks_bind_msg})"
    )
    if not ok_http_bind or not ok_socks_bind:
        perm_http = "operation not permitted" in http_bind_msg.lower()
        perm_socks = "operation not permitted" in socks_bind_msg.lower()
        if perm_http and perm_socks:
            print("  Hint: local socket checks were blocked by runtime permissions; skipping.")
        else:
            in_use_http = "in use" in http_bind_msg.lower() or "10048" in http_bind_msg
            in_use_socks = "in use" in socks_bind_msg.lower() or "10048" in socks_bind_msg
            if in_use_http and in_use_socks:
                print("  Hint: both ports are already in use (proxy likely running).")
            else:
                issues += 1
    else:
        print("  Hint: ports are free (proxy not currently running) or reusable.")

    auth_enabled = bool(config.get("proxy_auth_enabled", False))
    live_http_ok, live_http_msg = _probe_live_http_proxy(host, http_port, auth_enabled)
    live_socks_ok, live_socks_msg = _probe_live_socks5(socks_host, socks_port, auth_enabled)
    print(f"[HTTP proxy live]  {'OK' if live_http_ok else 'INFO'} ({live_http_msg})")
    print(f"[SOCKS5 live]      {'OK' if live_socks_ok else 'INFO'} ({live_socks_msg})")
    if ("ConnectionRefusedError" in live_http_msg and "ConnectionRefusedError" in live_socks_msg):
        print("  Hint: start `python main.py` first, then rerun --telegram-diagnose for live checks.")

    ca_ok = is_ca_trusted(CA_CERT_FILE)
    print(f"[CA trust]        {'OK' if ca_ok else 'FAIL'} ({CA_CERT_FILE})")
    for hint in ca_trust_hints(CA_CERT_FILE):
        print(f"  Hint: {hint}")
    if not ca_ok:
        issues += 1
        print("  Fix: run `python main.py --install-cert` then restart clients.")

    front_domain = str(config.get("front_domain", "www.google.com"))
    connect_ip = str(config.get("google_ip", "216.239.38.120"))
    ok_front, front_msg = asyncio.run(
        _probe_front_connect(front_domain, connect_ip, timeout=6.0)
    )
    print(
        f"[Front tunnel]    {'OK' if ok_front else 'FAIL'} "
        f"({front_domain} via {connect_ip}: {front_msg})"
    )
    if not ok_front and "operation not permitted" not in front_msg.lower():
        issues += 1
        print("  Fix: run `python main.py --scan` and use a reachable google_ip.")
    elif not ok_front:
        print("  Hint: outbound socket test blocked by runtime permissions; skipping.")

    ok_relay, relay_msg = asyncio.run(_probe_relay_latency(config))
    print(f"[Relay latency]   {'OK' if ok_relay else 'FAIL'} ({relay_msg})")
    if not ok_relay and "operation not permitted" not in relay_msg.lower():
        issues += 1
        print("  Fix: verify script_id/auth_key and Apps Script quota/deployment.")
    elif not ok_relay:
        print("  Hint: relay test blocked by runtime permissions; skipping.")

    if bool(config.get("proxy_auth_enabled", False)):
        user = str(config.get("proxy_username", "")).strip()
        pwd = str(config.get("proxy_password", "")).strip()
        auth_ok = bool(user and pwd)
        print(f"[Proxy auth]      {'OK' if auth_ok else 'FAIL'} (enabled)")
        if not auth_ok:
            issues += 1
            print("  Fix: set proxy_username and proxy_password.")
    else:
        print("[Proxy auth]      INFO (disabled)")

    print(
        f"[Telegram mode]   "
        f"{'ON' if config.get('telegram_desktop_mode', False) else 'OFF'}"
    )
    if not config.get("telegram_desktop_mode", False):
        print("  Hint: set telegram_desktop_mode=true for faster DC failover.")

    print("\nResult:")
    if issues == 0:
        print("  PASS - Telegram stack looks healthy.")
        print(f"  Telegram proxy (recommended): HTTP 127.0.0.1:{http_port}")
        return 0
    print(f"  NEEDS ATTENTION - {issues} issue(s) detected.")
    return 1


def main():
    args = parse_args()
    config_path = args.config

    try:
        with open(config_path) as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"Config not found: {config_path}")
        # Offer the interactive wizard if it's available and we're on a TTY.
        wizard = os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup.py")
        if os.path.exists(wizard) and sys.stdin.isatty():
            try:
                answer = input("Run the interactive setup wizard now? [Y/n]: ").strip().lower()
            except EOFError:
                answer = "n"
            if answer in ("", "y", "yes"):
                import subprocess
                rc = subprocess.call([sys.executable, wizard])
                if rc != 0:
                    sys.exit(rc)
                try:
                    with open(config_path) as f:
                        config = json.load(f)
                except Exception as e:
                    print(f"Could not load config after setup: {e}")
                    sys.exit(1)
            else:
                print("Copy config.example.json to config.json and fill in your values,")
                print("or run: python setup.py")
                sys.exit(1)
        else:
            print("Run: python setup.py   (or copy config.example.json to config.json)")
            sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in config: {e}")
        sys.exit(1)

    profile_name = str(config.get("profile", "")).strip()
    if profile_name in {"strict_tg", "balanced", "max_speed"}:
        config = _apply_runtime_profile(config, profile_name)

    if args.telegram_profile:
        config = _apply_telegram_profile(config)
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
            f.write("\n")
        print(f"Telegram profile applied and saved to: {config_path}")
        print("Recommended Telegram settings:")
        print("  HTTP proxy : 127.0.0.1:%d" % int(config["listen_port"]))
        print("  SOCKS5     : 127.0.0.1:%d" % int(config["socks5_port"]))
        print("  Proxy auth : disabled (proxy_auth_enabled=false)")
        print("Now run: python main.py")
        return

    if args.profile:
        config = _apply_runtime_profile(config, args.profile)
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
            f.write("\n")
        print(f"Profile '{args.profile}' applied and saved to: {config_path}")

    if args.telegram_diagnose:
        rc = _run_telegram_diagnose(config)
        sys.exit(rc)

    # Environment variable overrides
    if os.environ.get("DFT_AUTH_KEY"):
        config["auth_key"] = os.environ["DFT_AUTH_KEY"]
    if os.environ.get("DFT_SCRIPT_ID"):
        config["script_id"] = os.environ["DFT_SCRIPT_ID"]

    # CLI argument overrides
    if args.port is not None:
        config["listen_port"] = args.port
    elif os.environ.get("DFT_PORT"):
        config["listen_port"] = int(os.environ["DFT_PORT"])

    if args.host is not None:
        config["listen_host"] = args.host
    elif os.environ.get("DFT_HOST"):
        config["listen_host"] = os.environ["DFT_HOST"]

    if args.socks5_port is not None:
        config["socks5_port"] = args.socks5_port
    elif os.environ.get("DFT_SOCKS5_PORT"):
        config["socks5_port"] = int(os.environ["DFT_SOCKS5_PORT"])

    if args.disable_socks5:
        config["socks5_enabled"] = False

    if args.admin_port is not None:
        config["admin_port"] = args.admin_port
    elif os.environ.get("DFT_ADMIN_PORT"):
        config["admin_port"] = int(os.environ["DFT_ADMIN_PORT"])

    if args.disable_admin:
        config["admin_enabled"] = False
    elif os.environ.get("DFT_ADMIN_ENABLED") is not None:
        config["admin_enabled"] = os.environ["DFT_ADMIN_ENABLED"].strip() not in (
            "0", "false", "False", "no", "NO"
        )

    if args.telegram_desktop_mode:
        config["telegram_desktop_mode"] = True
    elif os.environ.get("DFT_TELEGRAM_DESKTOP_MODE") is not None:
        config["telegram_desktop_mode"] = os.environ["DFT_TELEGRAM_DESKTOP_MODE"].strip() not in (
            "0", "false", "False", "no", "NO"
        )

    if args.log_level is not None:
        config["log_level"] = args.log_level
    elif os.environ.get("DFT_LOG_LEVEL"):
        config["log_level"] = os.environ["DFT_LOG_LEVEL"]

    for key in ("auth_key",):
        if key not in config:
            print(f"Missing required config key: {key}")
            sys.exit(1)

    if config.get("auth_key", "") in _PLACEHOLDER_AUTH_KEYS:
        print(
            "Refusing to start: 'auth_key' is unset or uses a known placeholder.\n"
            "Pick a long random secret and set it in both config.json AND "
            "the AUTH_KEY constant inside Code.gs (they must match)."
        )
        sys.exit(1)

    # Always Apps Script mode — force-set for backward-compat configs.
    config["mode"] = "apps_script"
    sid = config.get("script_ids") or config.get("script_id")
    if not sid or (isinstance(sid, str) and sid == "YOUR_APPS_SCRIPT_DEPLOYMENT_ID"):
        print("Missing 'script_id' in config.")
        print("Deploy the Apps Script from Code.gs and paste the Deployment ID.")
        sys.exit(1)

    # ── Certificate installation ──────────────────────────────────────────
    if args.install_cert:
        setup_logging("INFO")
        _log = logging.getLogger("Main")
        _log.info("Installing CA certificate…")
        ok = install_ca(CA_CERT_FILE)
        sys.exit(0 if ok else 1)

    # ── Google IP Scanner ──────────────────────────────────────────────────
    if args.scan:
        setup_logging("INFO")
        front_domain = config.get("front_domain", "www.google.com")
        _log = logging.getLogger("Main")
        _log.info(f"Scanning Google IPs (fronting domain: {front_domain})")
        ok = scan_sync(front_domain)
        sys.exit(0 if ok else 1)

    setup_logging(config.get("log_level", "INFO"))
    log = logging.getLogger("Main")

    print_banner(__version__)
    log.info("DomainFront Tunnel starting (Apps Script relay)")

    log.info("Apps Script relay : SNI=%s → script.google.com",
             config.get("front_domain", "www.google.com"))
    script_ids = config.get("script_ids") or config.get("script_id")
    if isinstance(script_ids, list):
        log.info("Script IDs        : %d scripts (sticky per-host)", len(script_ids))
        for i, sid in enumerate(script_ids):
            log.info("  [%d] %s", i + 1, sid)
    else:
        log.info("Script ID         : %s", script_ids)

    # Ensure CA file exists before checking / installing it.
    # MITMCertManager generates ca/ca.crt on first instantiation.
    if not os.path.exists(CA_CERT_FILE):
        from mitm import MITMCertManager
        MITMCertManager()  # side-effect: creates ca/ca.crt + ca/ca.key

    # Auto-install MITM CA if not already trusted
    if not args.no_cert_check:
        if not is_ca_trusted(CA_CERT_FILE):
            log.warning("MITM CA is not trusted — attempting automatic installation…")
            ok = install_ca(CA_CERT_FILE)
            if ok:
                log.info("CA certificate installed. You may need to restart your browser.")
            else:
                log.error(
                    "Auto-install failed. Run with --install-cert (may need admin/sudo) "
                    "or manually install ca/ca.crt as a trusted root CA."
                )
        else:
            log.info("MITM CA is already trusted.")

    # ── LAN sharing configuration ────────────────────────────────────────
    lan_sharing = config.get("lan_sharing", False)
    if lan_sharing:
        # If LAN sharing is enabled and host is still localhost, change to all interfaces
        if config.get("listen_host", "127.0.0.1") == "127.0.0.1":
            config["listen_host"] = "0.0.0.0"
            log.info("LAN sharing enabled — listening on all interfaces")

    log.info("HTTP proxy         : %s:%d",
             config.get("listen_host", "127.0.0.1"),
             config.get("listen_port", 8080))
    if config.get("socks5_enabled", True):
        log.info("SOCKS5 proxy       : %s:%d",
                 config.get("socks5_host", config.get("listen_host", "127.0.0.1")),
                 config.get("socks5_port", 1080))

    # Log LAN access addresses if sharing is enabled
    if lan_sharing:
        socks_port = config.get("socks5_port", 1080) if config.get("socks5_enabled", True) else None
        log_lan_access(config.get("listen_port", 8080), socks_port)

    try:
        asyncio.run(_run(config))
    except KeyboardInterrupt:
        log.info("Stopped")


def _make_exception_handler(log):
    """Return an asyncio exception handler that silences Windows WinError 10054
    noise from connection cleanup (ConnectionResetError in
    _ProactorBasePipeTransport._call_connection_lost), which is harmless but
    verbose on Python/Windows when a remote host force-closes a socket."""
    def handler(loop, context):
        exc = context.get("exception")
        cb  = context.get("handle") or context.get("source_traceback", "")
        if (
            isinstance(exc, ConnectionResetError)
            and "_call_connection_lost" in str(cb)
        ):
            return  # suppress: benign Windows socket cleanup race
        log.error("[asyncio]  %s", context.get("message", context))
        if exc:
            loop.default_exception_handler(context)
    return handler


async def _run(config):
    loop = asyncio.get_running_loop()
    _log = logging.getLogger("asyncio")
    loop.set_exception_handler(_make_exception_handler(_log))
    server = ProxyServer(config)
    try:
        await server.start()
    finally:
        await server.stop()


if __name__ == "__main__":
    main()
