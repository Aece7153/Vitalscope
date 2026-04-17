# config.py
# Application-wide constants for Nextion Control Station.
# Edit values here — no other file needs changes for basic configuration.

# ── Serial ────────────────────────────────────────────────────────────────────

DEFAULT_BAUD  = 9600
DEFAULT_DELAY = 0.12    # seconds to wait between consecutive serial writes

# ── Discord integration ───────────────────────────────────────────────────────
# Paste your Discord webhook URL here, or leave blank and enter it in the UI.
# Format: https://discord.com/api/webhooks/<id>/<token>

DISCORD_WEBHOOK_URL = "URL"
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

NX_GREEN  = 11648
NX_RED    = 63488
NX_YELLOW = 65504
NX_GREY   = 33840
NX_WHITE  = 65535
NX_BLACK  = 0

# ── Page → refresh function map ───────────────────────────────────────────────

PAGE_REFRESH_MAP = {
    "main":      ["page_dashboard_refresh"],
    "dashboard": ["page_dashboard_refresh"],
    "network":   ["page_network_refresh"],
    "portscan":  ["page_portscan_refresh"],
    "proc":      ["page_procs_refresh"],      # Nextion prints "page_proc"
    "procs":     ["page_procs_refresh"],      # accept either spelling
    "lock":      ["page_lock_refresh"],
}

# ── Procs page auto-refresh interval ──────────────────────────────────────────
PROCS_REFRESH_INTERVAL = 120.0   # seconds (2 minutes)

# ── GUI colour palette ────────────────────────────────────────────────────────

BG        = "#0d0f12"
BG2       = "#13161b"
BG3       = "#1a1e26"
BORDER    = "#252a35"
ACCENT    = "#00e5ff"
ACCENT2   = "#ff6b35"
GREEN     = "#39ff14"
RED       = "#ff3131"
YELLOW    = "#ffd600"
TEXT      = "#c8d0e0"
TEXT_DIM  = "#4a5568"
TEXT_HEAD = "#e8edf5"

# ── Font tuples ───────────────────────────────────────────────────────────────

FONT_MONO    = ("Consolas", 9)
FONT_MONO_SM = ("Consolas", 8)
FONT_LABEL   = ("Consolas", 9, "bold")
FONT_HEAD    = ("Consolas", 11, "bold")
FONT_TITLE   = ("Consolas", 13, "bold")
