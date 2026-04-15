# config.py
# Application-wide constants for Nextion Control Station.
# Edit values here — no other file needs changes for basic configuration.

# ── Serial ────────────────────────────────────────────────────────────────────

DEFAULT_BAUD  = 9600
DEFAULT_DELAY = 0.12    # seconds to wait between consecutive serial writes

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
    "procs":     ["page_procs_refresh"],
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