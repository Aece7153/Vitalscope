# config.py
# Application-wide constants for Nextion Control Station.
# Edit values here — no other file needs changes for basic configuration.

# ── Serial ────────────────────────────────────────────────────────────────────

DEFAULT_BAUD  = 9600
DEFAULT_DELAY = 0.12    # seconds to wait between consecutive serial writes

# ── Discord integration ───────────────────────────────────────────────────────
# Paste your Discord webhook URL here, or leave blank and enter it in the UI.
# Format: https://discord.com/api/webhooks/<id>/<token>

DISCORD_WEBHOOK_URL = "https://discordapp.com/api/webhooks/1494356518009831464/WwkZ_kH3KbgdkzYwxdG3K6jz1X_yMkSE2b1k7micNTq7F5ff4bDtzhdTTbi8Tfgg_Z5a"
# ── Always-on monitor settings ────────────────────────────────────────────────

RESOURCE_POLL_INTERVAL  = 5.0    # seconds between CPU/RAM/disk polls
PROCESS_SCAN_INTERVAL   = 60.0   # seconds between process whitelist scans
SECURITY_SCAN_INTERVAL  = 600.0  # seconds between full firewall/port scans (10 min)

# Alert thresholds — Discord notification fires when usage exceeds these values
CPU_ALERT_THRESHOLD      = 85.0   # percent
RAM_ALERT_THRESHOLD      = 90.0   # percent
DISK_ALERT_THRESHOLD     = 90.0   # percent
PROCESS_RISK_THRESHOLD   = 60     # heuristic score 0–100; only alert above this

# Ports that trigger a "high-risk" flag in the security monitor
HIGH_RISK_PORTS_SET = frozenset({
    21, 22, 23, 25, 53, 80, 135, 137, 138, 139,
    443, 445, 1433, 3306, 3389, 5985, 5986, 8080, 8443,
})

# ── Known-safe process whitelist ───────────────────────────────────────────────
# Process names here (lowercase, filename only, no path) are considered trusted.
# Anything NOT in this set gets flagged as "unknown" — not necessarily malicious,
# but worth a manual review. Add your own regularly-used apps as needed.
#
# This is the single source of truth for "safe process names" across the app:
#   - security_scan.scan_processes() uses it to filter the flagged list.
#   - heuristic._SAFE_BASE_NAMES is derived from it (extensions stripped)
#     for typosquat distance checks.

KNOWN_SAFE_PROCESSES = frozenset({
    # Core Windows system processes
    "system", "system idle process", "registry", "smss.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
    "dwm.exe", "explorer.exe", "taskhostw.exe", "sihost.exe", "fontdrvhost.exe",
    "ctfmon.exe", "spoolsv.exe", "searchindexer.exe", "wuauclt.exe",
    "msiexec.exe", "conhost.exe", "dllhost.exe", "runtimebroker.exe",
    "applicationframehost.exe", "shellexperiencehost.exe",
    "startmenuexperiencehost.exe", "securityhealthservice.exe",
    "securityhealthsystray.exe", "msmpeng.exe", "nissrv.exe",
    "smartscreen.exe", "wlanext.exe", "audiodg.exe", "dashost.exe",
    "wermgr.exe", "wevtutil.exe",
    # Common browsers & productivity apps
    "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe",
    "code.exe", "python.exe", "pythonw.exe", "cmd.exe", "powershell.exe",
    "windowsterminal.exe", "notepad.exe", "notepad++.exe", "7zfm.exe",
    "discord.exe", "slack.exe", "teams.exe", "zoom.exe", "spotify.exe",
    "onedrive.exe", "dropbox.exe", "googledrivefs.exe",
    "taskmgr.exe", "mmc.exe", "regedit.exe", "mspaint.exe", "calc.exe",
    # Dev / serial / network tools commonly used with this project
    "thonny.exe", "putty.exe", "hxd.exe", "wireshark.exe",
})

# ── Network quality polling ───────────────────────────────────────────────────

PING_HOST      = "8.8.8.8"
PING_INTERVAL  = 3.0      # seconds between network quality score updates
QUALITY_GAUGE  = "j0"     # Nextion progress-bar element that shows quality score

# ── Nextion RGB565 colour constants ───────────────────────────────────────────
# RGB565 encodes colour as: (R[4:0] << 11) | (G[5:0] << 5) | B[4:0]
# These values match the Nextion editor's built-in colour palette.

NX_GREEN  = 11648   # bright green  — used for "connected / ok" states
NX_RED    = 63488   # bright red    — used for "error / disconnected" states
NX_YELLOW = 65504   # bright yellow — used for "warning / caution" states
NX_GREY   = 33840   # mid grey      — used for inactive / placeholder text
NX_WHITE  = 65535   # white
NX_BLACK  = 0       # black

# ── Page → refresh function map ───────────────────────────────────────────────
# Keys must exactly match the page name the Nextion prints (after "page_").
# Values are lists of method names on NextionControlStation that will be called
# in order whenever that page becomes active.
#
# To add a new page:
#   1. Add its entry here.
#   2. Implement page_<name>_refresh() in pages.py.
#   3. Add the page name to PAGE_NAMES in pico_bridge.py.

PAGE_REFRESH_MAP = {
    "main":      ["page_dashboard_refresh"],  # Pico boots to the main page
    "dashboard": ["page_dashboard_refresh"],
    "network":   ["page_network_refresh"],
    "portscan":  ["page_portscan_refresh"],
    "lock":      ["page_lock_refresh"],
}

# ── GUI colour palette ────────────────────────────────────────────────────────
# All Tkinter colours. Edit here to restyle the whole application at once.

BG        = "#0d0f12"   # main window background
BG2       = "#13161b"   # panel / section background
BG3       = "#1a1e26"   # widget / card background
BORDER    = "#252a35"   # subtle border lines
ACCENT    = "#00e5ff"   # primary highlight (cyan)
ACCENT2   = "#ff6b35"   # secondary highlight (orange)
GREEN     = "#39ff14"   # status: OK / connected
RED       = "#ff3131"   # status: error / disconnected
YELLOW    = "#ffd600"   # status: warning / caution
TEXT      = "#c8d0e0"   # normal text
TEXT_DIM  = "#4a5568"   # de-emphasised / label text
TEXT_HEAD = "#e8edf5"   # heading / card-name text

# ── Font tuples ───────────────────────────────────────────────────────────────
# Tkinter font tuples: (family, size[, style])

FONT_MONO    = ("Consolas", 9)
FONT_MONO_SM = ("Consolas", 8)
FONT_LABEL   = ("Consolas", 9, "bold")
FONT_HEAD    = ("Consolas", 11, "bold")
FONT_TITLE   = ("Consolas", 13, "bold")