# Tray Status Indicator (Windows 11)

A lightweight system-tray app that draws a small **holo ring** icon in the
tray: five colored arc segments arranged around a circle, each separated
by a gap, that only light up and blink when their signal is active. A
center dot summarizes at a glance whether anything is live right now
(green = all clear, otherwise it shows the color of the active signal).

Right-click the icon and choose **"Locate threat / activity source"** to
see exactly *what* triggered each light - which app is using the camera,
which process is screen-sharing, what Defender actually detected (and
where), and which URL was flagged unsafe - instead of just a color.

The five signals:

| Signal                | Color   | Source of truth                                              |
|------------------------|---------|----------------------------------------------------------------|
| Camera in use          | Green   | Windows' own camera-usage registry data                       |
| Microphone in use      | Red     | Windows' own microphone-usage registry data                   |
| Screen share/record    | Blue    | Heuristic: known screen-share/record apps running             |
| Malware / threat       | Purple  | Windows Defender's own real-time status (real threat detections, or real-time protection disabled) |
| Unsafe website         | Orange  | Companion browser extension: Safe Browsing + local heuristics |

The icon sits in the system tray - by default Windows 11 puts new tray icons
in the **hidden icons (overflow) area**, matching what you asked for.

## Important, please read

This is a personal convenience/awareness tool, not a certified security
product:

- The **malware/threat** dot reflects what Windows Defender itself already
  knows and reports - it does not scan files or replace antivirus software.
  If you use a different antivirus, Defender's live-protection status may
  not reflect your actual protection state.
- The **unsafe website** dot is best-effort. The local heuristics catch
  some common phishing patterns but will miss novel attacks and can
  occasionally flag legitimate sites; Google Safe Browsing (optional, your
  own free API key) adds a real reputation-database check, but no check is
  100% complete. Don't treat "no orange light" as a guarantee a site is
  safe.

## How to build the .exe

`.exe` files must be built on a Windows machine (no reliable Windows
cross-compile from Linux). It's one double-click:

1. Copy this whole folder to your Windows 11 PC.
2. Install Python 3.9+ (check "Add python.exe to PATH" during setup).
3. Double-click **`build_exe.bat`**. It installs dependencies and builds.
4. Your app: `dist\TrayStatusIndicator.exe`

Run it automatically at login: press `Win + R` -> `shell:startup` -> Enter,
then drop `TrayStatusIndicator.exe` (or a shortcut) into that folder.

## Set up the browser extension (for the orange "unsafe website" dot)

The desktop app can't see inside your browser on its own - the extension
is what watches the active tab and reports back over localhost only.

**1. Get your pairing token**
Run the tray app, right-click its icon, choose **"Show pairing token"**.
Keep that popup open for the next step.

**2. Load the extension (Chrome, Edge, Brave - any Chromium browser)**
1. Go to `chrome://extensions` (or `edge://extensions`).
2. Turn on **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the `browser_extension` folder from
   this project.
4. Click the puzzle-piece icon in your toolbar, find "Tray Status
   Indicator - Website Safety Reporter," and open its **Details -> Extension
   options** (or right-click its toolbar icon -> Options).
5. Paste the **pairing token** from step 1.
6. (Optional but recommended) Add a free **Google Safe Browsing API key** -
   get one at
   https://developers.google.com/safe-browsing/v4/get-started
   Without a key, the extension still works using local heuristics alone.
7. Click **Save**.

Repeat "Load unpacked" in each Chromium browser you use (Chrome, Edge,
Brave, etc. each need it loaded separately - the extension isn't published
to a store, it runs locally as an unpacked extension).

**Firefox note:** this extension is written for Manifest V3 (Chromium).
Firefox support would need a small manifest tweak (`background.scripts`
instead of `service_worker`) - ask if you'd like a Firefox-compatible copy.

## How each signal actually works

- **Camera / Microphone**: read from
  `HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore`
  - the same live data Windows' built-in in-use indicators use.

- **Screen sharing/recording**: checks running processes against
  `SCREEN_SHARE_PROCESSES` in `tray_indicator.py` (OBS, Zoom, Teams,
  Discord, TeamViewer, AnyDesk, Bandicam, Xbox Game Bar recorder, etc.).
  Add your own app's `.exe` name (check Task Manager -> Details) if it's
  missing from the list.

- **Malware/threat**: runs `Get-MpComputerStatus` and
  `Get-MpThreatDetection` via PowerShell (built into Windows) every few
  polling cycles, and lights up if Defender reports an active threat
  detection or real-time protection turned off.

- **Unsafe website**: the browser extension scores the active tab's URL
  using:
  - raw IP-address links
  - punycode (`xn--`) look-alike domains
  - brand-impersonation patterns (e.g. `paypal-secure-login.xyz`)
  - risky/abused TLDs (`.zip`, `.top`, `.xyz`, `.tk`, etc. - weak signal)
  - non-HTTPS pages with login/account-like URLs
  - optionally, Google Safe Browsing's real threat-intelligence database

  and POSTs the result to `http://127.0.0.1:8765/report` on your own
  machine only, guarded by the pairing token so other local apps can't
  spoof it.

## Customizing

Top of `tray_indicator.py`:
- `POLL_INTERVAL_SECONDS`, `BLINK_INTERVAL_SECONDS`
- `COLOR_*` constants for each dot
- `SCREEN_SHARE_PROCESSES` list
- `LOCAL_SERVER_PORT` (must match the extension's `REPORT_ENDPOINT` in
  `browser_extension/background.js` if you change it)

After editing, re-run `build_exe.bat` to rebuild.

## Menu

Right-click (or left-click) the tray icon for:
- Live status summary (all five signals)
- **Refresh now**
- **Locate threat / activity source** - shows which app/process/URL is
  behind each active light
- **Show pairing token** (for extension setup)
- **Exit**
