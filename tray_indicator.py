"""
Tray Status Indicator for Windows 11
-------------------------------------
System-tray app with FIVE colored dots that blink when active:

    CAMERA          -> GREEN    (webcam in use)
    MICROPHONE      -> RED      (mic in use)
    SCREEN SHARE    -> BLUE     (screen recording / sharing app running)
    MALWARE/THREAT  -> PURPLE   (Windows Defender reports an active threat,
                                  or real-time protection is off)
    UNSAFE WEBSITE  -> ORANGE   (the active browser tab looks unsafe, per
                                  Google Safe Browsing + local heuristics,
                                  reported by the companion browser extension)

Detection sources
------------------
Camera / Microphone:
    Windows 11's own CapabilityAccessManager consent-store registry keys
    (the same data source the built-in camera/mic-in-use indicators use).
    No admin rights needed.

Screen sharing / recording:
    Heuristic - checks the running process list against a list of common
    screen-share/record/remote-control apps (edit SCREEN_SHARE_PROCESSES).

Malware / threat:
    Reads REAL data from Windows Defender via PowerShell:
        Get-MpComputerStatus      -> is real-time protection on?
        Get-MpThreatDetection     -> any currently-active threat detections?
    This does not reimplement antivirus scanning - it surfaces Defender's
    own live status. No admin rights needed to read this.

Unsafe website:
    This app cannot see inside your browser by itself (no app can, safely).
    A small companion browser extension (in browser_extension/) reads the
    active tab's URL, checks it against Google Safe Browsing (optional, your
    own free API key) plus local heuristics (IP-literal host, punycode
    homograph domains, brand-impersonation patterns), and reports the
    result to this app over a local-only HTTP endpoint
    (http://127.0.0.1:8765/report). See README.md to install the extension.

Requires: Windows 10/11, Python 3.9+ to build. End users just run the .exe.
"""

import sys
import os
import io
import json
import time
import uuid
import threading
import subprocess

if sys.platform != "win32":
    print("This application only runs on Windows.")
    sys.exit(1)

import ctypes
import winreg
import psutil
from PIL import Image, ImageDraw
import pystray
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

POLL_INTERVAL_SECONDS = 1.0        # camera/mic/process/defender re-check interval
DEFENDER_POLL_EVERY_N = 5          # only call PowerShell every Nth poll (it's slower)
BLINK_INTERVAL_SECONDS = 0.5
LOCAL_SERVER_PORT = 8765
BROWSER_STATUS_STALE_SECONDS = 30  # if extension hasn't reported in this long, treat as "unknown" (safe)

# Colors (R, G, B)
COLOR_CAMERA_ON = (0, 200, 0)          # green
COLOR_MIC_ON = (220, 30, 30)           # red
COLOR_SCREEN_ON = (30, 90, 230)        # blue
COLOR_MALWARE_ON = (150, 30, 200)      # purple
COLOR_UNSAFE_SITE_ON = (255, 140, 0)   # orange
COLOR_OFF = (90, 90, 90)               # dim gray when inactive
COLOR_DIM_FACTOR = 0.35

SCREEN_SHARE_PROCESSES = [
    "obs64.exe", "obs32.exe", "obs.exe",
    "zoom.exe",
    "teams.exe", "ms-teams.exe",
    "discord.exe",
    "slack.exe",
    "skype.exe",
    "teamviewer.exe",
    "anydesk.exe",
    "gotomeeting.exe",
    "webexmta.exe", "webex.exe", "atmgr.exe",
    "gamebarftserver.exe",
    "nvcontainer.exe",
    "bandicam.exe",
    "camtasia.exe",
    "screenrec.exe",
    "actionrecorder.exe",
]

APP_DATA_DIR = os.path.join(os.environ.get("LOCALAPPDATA", "."), "TrayStatusIndicator")
TOKEN_FILE = os.path.join(APP_DATA_DIR, "pairing_token.txt")

# --------------------------------------------------------------------------
# Pairing token (simple shared secret so random local processes can't spoof
# the browser-safety endpoint). Not enterprise-grade auth - just a basic
# guard for a personal loopback endpoint.
# --------------------------------------------------------------------------

def get_or_create_pairing_token() -> str:
    os.makedirs(APP_DATA_DIR, exist_ok=True)
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, "r", encoding="utf-8") as f:
                token = f.read().strip()
                if token:
                    return token
        except OSError:
            pass
    token = uuid.uuid4().hex
    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        f.write(token)
    return token


# --------------------------------------------------------------------------
# Camera / Microphone detection (Windows consent store)
# --------------------------------------------------------------------------

def _friendly_app_name(subkey_name: str) -> str:
    """
    ConsentStore subkey names are either a package family name
    (e.g. 'Microsoft.WindowsCamera_8wekyb3d8bbwe') for Store apps, or a
    filesystem path to the .exe for classic desktop apps. Trim both down
    to something readable for the "which app" detail view.
    """
    name = subkey_name
    if "#" in name:
        name = name.split("#")[-1]
    if "\\" in name:
        name = name.split("\\")[-1]
    if "_" in name and not name.lower().endswith(".exe"):
        name = name.split("_")[0]
    return name or subkey_name


def _capability_in_use(capability_name: str):
    """
    Returns (active: bool, apps: list[str]) - apps currently holding the
    capability open, so we can show *what* is using the camera/mic, not
    just that something is.
    """
    base = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
    paths_to_check = [
        f"{base}\\{capability_name}",
        f"{base}\\{capability_name}\\NonPackaged",
    ]
    active_apps = []
    for path in paths_to_check:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
                index = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, index)
                    except OSError:
                        break
                    index += 1
                    try:
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            try:
                                stop_time, _ = winreg.QueryValueEx(subkey, "LastUsedTimeStop")
                                if stop_time == 0:
                                    active_apps.append(_friendly_app_name(subkey_name))
                            except FileNotFoundError:
                                pass
                    except OSError:
                        continue
        except FileNotFoundError:
            continue
    return (len(active_apps) > 0), active_apps


def is_camera_active():
    return _capability_in_use("webcam")


def is_mic_active():
    return _capability_in_use("microphone")


def is_screen_share_active():
    """Returns (active: bool, matched_processes: list[str])."""
    try:
        running = {p.name().lower() for p in psutil.process_iter(["name"])}
    except Exception:
        return False, []
    targets = {p.lower() for p in SCREEN_SHARE_PROCESSES}
    matched = sorted(running & targets)
    return (len(matched) > 0), matched


# --------------------------------------------------------------------------
# Malware / threat detection via Windows Defender's own reported status
# --------------------------------------------------------------------------

def _run_powershell_json(command: str, timeout=6):
    """
    Runs a PowerShell command that outputs ConvertTo-Json and returns the
    parsed result (dict, list, or None on failure/empty).
    """
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        out = completed.stdout.strip()
        if not out:
            return None
        return json.loads(out)
    except Exception:
        return None


def get_defender_status():
    """
    Returns a dict:
        {
          "available": bool,               # could we query Defender at all?
          "realtime_protection_on": bool,
          "active_threats": int,           # count of currently-detected, unresolved threats
        }
    """
    result = {"available": False, "realtime_protection_on": True, "active_threats": 0, "threat_details": []}

    status = _run_powershell_json(
        "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled | ConvertTo-Json -Compress"
    )
    if status is not None:
        result["available"] = True
        if isinstance(status, dict):
            result["realtime_protection_on"] = bool(status.get("RealTimeProtectionEnabled", True))

    threats = _run_powershell_json(
        "Get-MpThreatDetection | Select-Object ThreatName, Resources, ProcessName | ConvertTo-Json -Compress"
    )
    if threats is not None:
        result["available"] = True
        if isinstance(threats, dict):
            threats = [threats]
        if isinstance(threats, list):
            result["active_threats"] = len(threats)
            details = []
            for t in threats:
                if not isinstance(t, dict):
                    continue
                name = t.get("ThreatName") or "Unknown threat"
                resources = t.get("Resources")
                if isinstance(resources, list):
                    location = resources[0] if resources else (t.get("ProcessName") or "unknown location")
                else:
                    location = resources or t.get("ProcessName") or "unknown location"
                details.append(f"{name}  ->  {location}")
            result["threat_details"] = details

    return result


def is_malware_alert_active(defender_status: dict) -> bool:
    if not defender_status.get("available"):
        return False
    if defender_status.get("active_threats", 0) > 0:
        return True
    if not defender_status.get("realtime_protection_on", True):
        return True
    return False


# --------------------------------------------------------------------------
# Unsafe-website status, reported by the companion browser extension over
# a local-only HTTP endpoint.
# --------------------------------------------------------------------------

class BrowserSafetyState:
    def __init__(self, token: str):
        self.token = token
        self.lock = threading.Lock()
        self.unsafe = False
        self.last_url = ""
        self.last_reasons = []
        self.last_update_ts = 0.0

    def report(self, url: str, safe: bool, reasons):
        with self.lock:
            self.last_url = url
            self.unsafe = (not safe)
            self.last_reasons = reasons or []
            self.last_update_ts = time.time()

    def is_unsafe_and_fresh(self) -> bool:
        with self.lock:
            if not self.unsafe:
                return False
            if time.time() - self.last_update_ts > BROWSER_STATUS_STALE_SECONDS:
                return False
            return True

    def summary(self) -> str:
        with self.lock:
            if time.time() - self.last_update_ts > BROWSER_STATUS_STALE_SECONDS:
                return "no recent report from browser extension"
            state = "UNSAFE" if self.unsafe else "safe"
            reasons = ", ".join(self.last_reasons) if self.last_reasons else "-"
            return f"{state} ({self.last_url}) reasons: {reasons}"


def make_report_handler(state: BrowserSafetyState):
    class ReportHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # silence default logging

        def _unauthorized(self):
            self.send_response(401)
            self.end_headers()

        def do_POST(self):
            if self.path.split("?")[0] != "/report":
                self.send_response(404)
                self.end_headers()
                return
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                data = json.loads(body.decode("utf-8"))
            except Exception:
                self.send_response(400)
                self.end_headers()
                return

            if data.get("token") != state.token:
                self._unauthorized()
                return

            url = str(data.get("url", ""))[:2048]
            safe = bool(data.get("safe", True))
            reasons = data.get("reasons", [])
            if not isinstance(reasons, list):
                reasons = [str(reasons)]
            state.report(url, safe, reasons)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        def do_GET(self):
            # simple health check
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    return ReportHandler


def start_local_server(state: BrowserSafetyState):
    handler_cls = make_report_handler(state)
    server = ThreadingHTTPServer(("127.0.0.1", LOCAL_SERVER_PORT), handler_cls)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


# --------------------------------------------------------------------------
# Icon drawing - "holo ring": 5 colored arc segments around a circle, each
# separated by a gap, each glowing/blinking only when its signal is active.
# The center shows a single small status dot summarizing everything at a
# glance (what you'd see when the icon is shrunk down in the tray).
# --------------------------------------------------------------------------

SEGMENT_ORDER = [
    ("camera", COLOR_CAMERA_ON),
    ("mic", COLOR_MIC_ON),
    ("screen", COLOR_SCREEN_ON),
    ("malware", COLOR_MALWARE_ON),
    ("website", COLOR_UNSAFE_SITE_ON),
]
SEGMENT_GAP_DEGREES = 10  # gap between each arc segment


def _scale_color(color, factor):
    return tuple(max(0, min(255, int(c * factor))) for c in color)


def _draw_glow_arc(draw, img, cx, cy, radius, thickness, start_deg, end_deg, color, glow=True):
    bbox = [cx - radius, cy - radius, cx + radius, cy + radius]
    if glow:
        # Soft outer glow: a few progressively wider/fainter passes underneath
        glow_layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
        glow_draw = ImageDraw.Draw(glow_layer)
        for i, pad in enumerate((10, 6, 3)):
            alpha = int(70 / (i + 1))
            glow_draw.arc(
                [cx - radius - pad, cy - radius - pad, cx + radius + pad, cy + radius + pad],
                start_deg, end_deg, fill=color + (alpha,), width=thickness + pad * 2,
            )
        img.alpha_composite(glow_layer)
        draw = ImageDraw.Draw(img)
    draw.arc(bbox, start_deg, end_deg, fill=color + (255,), width=thickness)


def build_icon_image(states: dict, blink_phase_bright: bool, size=132):
    """
    states: dict with keys camera, mic, screen, malware, website -> bool
    """
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))

    cx, cy = size / 2, size / 2
    radius = size * 0.36
    thickness = max(6, int(size * 0.13))

    n = len(SEGMENT_ORDER)
    sweep = 360 / n
    any_active = any(states.get(k, False) for k, _ in SEGMENT_ORDER)

    # Base ring: faint track so the holo shape reads even when nothing is on
    base_draw = ImageDraw.Draw(img)
    for i, (key, base_color) in enumerate(SEGMENT_ORDER):
        start_deg = -90 + i * sweep + SEGMENT_GAP_DEGREES / 2
        end_deg = -90 + (i + 1) * sweep - SEGMENT_GAP_DEGREES / 2
        active = states.get(key, False)

        if active:
            color = base_color if blink_phase_bright else _scale_color(base_color, COLOR_DIM_FACTOR)
            _draw_glow_arc(base_draw, img, cx, cy, radius, thickness, start_deg, end_deg, color, glow=blink_phase_bright)
        else:
            base_draw.arc(
                [cx - radius, cy - radius, cx + radius, cy + radius],
                start_deg, end_deg, fill=COLOR_OFF + (140,), width=max(3, thickness // 2),
            )
        base_draw = ImageDraw.Draw(img)

    # Center status dot: summarizes "is anything live right now"
    center_r = size * 0.16
    if any_active:
        # priority order for the center color when multiple are active
        for key, base_color in SEGMENT_ORDER:
            if states.get(key, False):
                center_color = base_color
                break
        center_color = center_color if blink_phase_bright else _scale_color(center_color, COLOR_DIM_FACTOR)
    else:
        center_color = (60, 200, 120)  # calm green "all clear"

    center_layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
    center_draw = ImageDraw.Draw(center_layer)
    if any_active:
        for pad, alpha in ((8, 40), (4, 70)):
            center_draw.ellipse(
                [cx - center_r - pad, cy - center_r - pad, cx + center_r + pad, cy + center_r + pad],
                fill=center_color + (alpha,),
            )
    img.alpha_composite(center_layer)
    center_draw = ImageDraw.Draw(img)
    center_draw.ellipse(
        [cx - center_r, cy - center_r, cx + center_r, cy + center_r],
        fill=center_color + (255,),
        outline=(255, 255, 255, 160),
        width=2,
    )

    return img


# --------------------------------------------------------------------------
# Main application
# --------------------------------------------------------------------------

class TrayStatusIndicator:
    def __init__(self):
        self.states = {
            "camera": False, "mic": False, "screen": False,
            "malware": False, "website": False,
        }
        self.details = {
            "camera": [], "mic": [], "screen": [],
            "malware": [], "website": "",
        }
        self.blink_phase = True
        self._stop_event = threading.Event()
        self._poll_count = 0
        self._defender_status_cache = {"available": False, "realtime_protection_on": True, "active_threats": 0}

        self.token = get_or_create_pairing_token()
        self.browser_state = BrowserSafetyState(self.token)
        self.server = start_local_server(self.browser_state)

        self.icon = pystray.Icon(
            "TrayStatusIndicator",
            build_icon_image(self.states, True),
            self._status_text(),
            menu=pystray.Menu(
                pystray.MenuItem(self._status_text, None, enabled=False),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Refresh now", self._force_refresh),
                pystray.MenuItem("Locate threat / activity source", self._show_locate_details),
                pystray.MenuItem("Show pairing token (for browser extension)", self._show_token),
                pystray.MenuItem("Exit", self._exit),
            ),
        )

    def _status_text(self, item=None):
        s = self.states
        return (
            f"Cam:{'ON' if s['camera'] else 'off'} "
            f"Mic:{'ON' if s['mic'] else 'off'} "
            f"Share:{'ON' if s['screen'] else 'off'} "
            f"Threat:{'ON' if s['malware'] else 'off'} "
            f"Site:{'UNSAFE' if s['website'] else 'ok'}"
        )

    def _show_token(self, icon=None, item=None):
        message = (
            f"Pairing token (paste into the browser extension's options page):\n\n"
            f"{self.token}\n\n"
            f"Local endpoint: http://127.0.0.1:{LOCAL_SERVER_PORT}/report"
        )
        # MessageBoxW avoids pulling in tkinter; MB_ICONINFORMATION = 0x40
        threading.Thread(
            target=lambda: ctypes.windll.user32.MessageBoxW(0, message, "Tray Status Indicator", 0x40),
            daemon=True,
        ).start()

    def _force_refresh(self, icon=None, item=None):
        self._poll_state(force_defender=True)

    def _show_locate_details(self, icon=None, item=None):
        s, d = self.states, self.details
        lines = ["Where each signal is coming from right now:", ""]

        lines.append("Camera: " + (", ".join(d["camera"]) if s["camera"] else "not in use"))
        lines.append("Microphone: " + (", ".join(d["mic"]) if s["mic"] else "not in use"))
        lines.append("Screen share/record: " + (", ".join(d["screen"]) if s["screen"] else "not detected"))

        if s["malware"]:
            if d["malware"]:
                lines.append("Threat: " + " | ".join(d["malware"]))
            else:
                lines.append("Threat: real-time protection is OFF (no active detections)")
        else:
            lines.append("Threat: none - Defender reports clean")

        lines.append("Website: " + (d["website"] or "no recent unsafe report"))

        message = "\n".join(lines)
        threading.Thread(
            target=lambda: ctypes.windll.user32.MessageBoxW(0, message, "Locate Threat / Activity Source", 0x40),
            daemon=True,
        ).start()

    def _exit(self, icon=None, item=None):
        self._stop_event.set()
        try:
            self.server.shutdown()
        except Exception:
            pass
        self.icon.stop()

    def _poll_state(self, force_defender=False):
        self.states["camera"], self.details["camera"] = is_camera_active()
        self.states["mic"], self.details["mic"] = is_mic_active()
        self.states["screen"], self.details["screen"] = is_screen_share_active()

        self._poll_count += 1
        if force_defender or self._poll_count % DEFENDER_POLL_EVERY_N == 0:
            self._defender_status_cache = get_defender_status()
        self.states["malware"] = is_malware_alert_active(self._defender_status_cache)
        self.details["malware"] = self._defender_status_cache.get("threat_details", [])

        self.states["website"] = self.browser_state.is_unsafe_and_fresh()
        self.details["website"] = self.browser_state.summary() if self.states["website"] else ""

        self.icon.title = self._status_text()

    def _poll_loop(self):
        last_poll = 0.0
        while not self._stop_event.is_set():
            now = time.time()
            if now - last_poll >= POLL_INTERVAL_SECONDS:
                self._poll_state()
                last_poll = now

            self.blink_phase = not self.blink_phase
            self.icon.icon = build_icon_image(self.states, self.blink_phase)
            time.sleep(BLINK_INTERVAL_SECONDS)

    def run(self):
        t = threading.Thread(target=self._poll_loop, daemon=True)
        t.start()
        self.icon.run()


def main():
    app = TrayStatusIndicator()
    app.run()


if __name__ == "__main__":
    main()
