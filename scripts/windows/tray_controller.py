#!/usr/bin/env python3
"""Windows tray controller for MasterHttpRelayVPN.

Features:
- Toggle VPN ON/OFF via admin API
- Open dashboard in default browser
- Start relay process (start.bat)
- Probe relay health quickly
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

try:
    import pystray
    from PIL import Image, ImageDraw
except Exception as exc:  # pragma: no cover
    print("Tray dependencies missing. Install with:")
    print("  py -3 -m pip install pystray pillow")
    print(f"Details: {exc}")
    sys.exit(1)


ADMIN = os.environ.get("MHRVPN_ADMIN_URL", "http://127.0.0.1:9090")
TOKEN = os.environ.get("MHRVPN_ADMIN_TOKEN", "").strip()
ROOT = Path(__file__).resolve().parents[2]
START_BAT = ROOT / "start.bat"

state = {"enabled": None, "connected": False}


def _headers() -> dict[str, str]:
    h = {"Content-Type": "application/json"}
    if TOKEN:
        h["X-Admin-Token"] = TOKEN
    return h


def _request(path: str, method: str = "GET", body: dict | None = None) -> dict:
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(ADMIN + path, data=data, method=method)
    for k, v in _headers().items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=4) as resp:
        raw = resp.read() or b"{}"
    return json.loads(raw.decode("utf-8", errors="replace"))


def poll_state(icon: pystray.Icon) -> None:
    while True:
        try:
            data = _request("/api/service")
            state["enabled"] = bool(data.get("enabled", True))
            state["connected"] = True
        except Exception:
            state["connected"] = False
            state["enabled"] = None
        icon.title = build_title()
        time.sleep(2)


def build_title() -> str:
    if not state["connected"]:
        return "MasterHttpRelayVPN: Disconnected"
    return f"MasterHttpRelayVPN: {'ON' if state['enabled'] else 'OFF'}"


def set_enabled(enabled: bool) -> None:
    _request("/api/service", method="POST", body={"enabled": enabled})


def action_toggle(icon: pystray.Icon, item) -> None:
    try:
        current = bool(state["enabled"]) if state["enabled"] is not None else True
        set_enabled(not current)
    except Exception:
        pass


def action_open_dashboard(icon: pystray.Icon, item) -> None:
    webbrowser.open(ADMIN + "/")


def action_start_relay(icon: pystray.Icon, item) -> None:
    if START_BAT.exists():
        subprocess.Popen(["cmd.exe", "/c", str(START_BAT)], cwd=str(ROOT))


def action_probe(icon: pystray.Icon, item) -> None:
    try:
        _request("/api/quick-action", method="POST", body={"action": "probe_relay"})
    except Exception:
        pass


def action_exit(icon: pystray.Icon, item) -> None:
    icon.stop()


def create_image() -> Image.Image:
    img = Image.new("RGB", (64, 64), "#0f1c33")
    d = ImageDraw.Draw(img)
    d.rectangle((8, 8, 56, 56), outline="#39c6ff", width=3)
    d.rectangle((18, 26, 46, 38), fill="#5ee1a2")
    return img


def build_menu() -> pystray.Menu:
    return pystray.Menu(
        pystray.MenuItem("Toggle ON/OFF", action_toggle),
        pystray.MenuItem("Open Dashboard", action_open_dashboard),
        pystray.MenuItem("Start Relay", action_start_relay),
        pystray.MenuItem("Relay Probe", action_probe),
        pystray.MenuItem("Exit", action_exit),
    )


def main() -> None:
    icon = pystray.Icon("mhrvpn", create_image(), "MasterHttpRelayVPN", build_menu())
    t = threading.Thread(target=poll_state, args=(icon,), daemon=True)
    t.start()
    icon.run()


if __name__ == "__main__":
    main()
