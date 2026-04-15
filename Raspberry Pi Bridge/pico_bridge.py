# pico_bridge.py  (runs on the Raspberry Pi Pico)
# USB CDC  ←→  Pico  ←→  Nextion (UART0)
#
# Bridges serial commands from the PC application to the Nextion display,
# and forwards Nextion print output back to the PC over USB.

from machine import UART, Pin
import sys
import time
import select


# ── Configuration ─────────────────────────────────────────────────────────────

NEXTION_BAUD   = 9600
NEXTION_TERM   = b'\xff\xff\xff'  # required 3-byte terminator for every Nextion command
NEXTION_TX     = 16               # GPIO pin connected to Nextion RX
NEXTION_RX     = 17               # GPIO pin connected to Nextion TX
BOOT_DELAY_S   = 5               # seconds to wait for Nextion to finish its own startup

# Prefixes that require an explicit page switch to main before the command is sent.
# These element names only exist on the main/dashboard page.
DASHBOARD_PREFIXES = ("pi_", "cpu_", "ram_", "disk_")


# ── Hardware setup ────────────────────────────────────────────────────────────

nextion = UART(0, baudrate=NEXTION_BAUD, tx=NEXTION_TX, rx=NEXTION_RX)

# Onboard LED stays lit while the bridge is running; useful as a power indicator
led = Pin("LED", Pin.OUT)
led.on()

print("[PICO] READY")


# ── Nextion helpers ───────────────────────────────────────────────────────────

def _nextion_flush():
    """Discard all bytes currently waiting in the Nextion UART receive buffer."""
    while nextion.any():
        nextion.read(nextion.any())


def send_to_nextion(cmd):
    """
    Encode and write one command to the Nextion with the required terminator.

    Accepts str or bytes. Strings are encoded to ASCII before sending.
    """
    if isinstance(cmd, str):
        cmd = cmd.encode("ascii")
    nextion.write(cmd + NEXTION_TERM)


def nextion_get(component):
    """
    Query a Nextion element's current value using the 'get <component>' command.

    Sends the query, then waits up to 500 ms for a 0x70 string response packet.
    The response format is:  0x70  <ASCII string>  0xFF 0xFF 0xFF

    Args:
        component: Nextion element attribute string (e.g. "va0.txt")

    Returns:
        The element's string value, or None if the query timed out or failed.
    """
    _nextion_flush()  # discard stale bytes before issuing the query
    send_to_nextion("get {}".format(component))

    deadline = time.ticks_add(time.ticks_ms(), 500)
    buf      = bytearray()

    while time.ticks_diff(deadline, time.ticks_ms()) > 0:
        if nextion.any():
            buf.extend(nextion.read(nextion.any()))
            # A complete response ends with the 3-byte terminator
            if len(buf) >= 4 and buf[-3:] == NEXTION_TERM:
                break
        time.sleep_ms(5)

    # 0x70 = string response code; anything else (or timeout) is a failure
    if not buf or buf[0] != 0x70:
        return None

    try:
        return buf[1:-3].decode("ascii", errors="ignore").strip()
    except Exception:
        return None


# ── Page-load actions ─────────────────────────────────────────────────────────

# All Nextion page names that the Pico should recognise and forward to the PC.
# Add new page names here as you add pages to the Nextion project.
PAGE_NAMES = [
    b"page_dashboard",
    b"page_network",
    b"page_portscan",
    b"page_main",
    b"page_lock",
    b"page_procs",
]


def on_page_load(page_name):
    """
    Perform Pico-side actions triggered when a specific page becomes active.

    This runs immediately on the Pico (no round-trip to the PC) so that
    pi_status can update as fast as possible without waiting for USB latency.

    Args:
        page_name: the decoded page name string (e.g. "page_dashboard")
    """
    if page_name == "page_dashboard":
        send_to_nextion('pi_status.txt="Connected"')
        send_to_nextion("pi_status.pco=11648")  # 11648 = NX_GREEN (RGB565)
        print("[PICO] pi_status -> Connected (green)")


def handle_nextion_message(raw_bytes):
    """
    Scan raw bytes from the Nextion UART for page names and port values.

    The Nextion print() statements for a single page load often arrive together
    in one nextion.read() chunk, for example:

        page_portscan  \\xFF\\xFF\\xFF  port_444  \\xFF\\xFF\\xFF

    So we NEVER return early after finding a page name — we always scan the
    full raw_bytes for a port_ token too before returning.

    Forwarding strategy:
        - Page names  → printed to stdout so the PC app can detect page changes.
        - port_XXXX   → printed as "portscan_init XXXX" to trigger a scan on PC.
        - Anything else → printed as "[NEX_MSG] <text>" for debug visibility.

    Args:
        raw_bytes: raw bytes read from the Nextion UART in one call
    """
    if not raw_bytes:
        return

    # Decode once; errors='ignore' silently drops binary bytes (e.g. 0xFF terminators)
    try:
        text = raw_bytes.decode("ascii", errors="ignore").strip()
    except Exception:
        text = ""

    # ── 1. Scan for a recognised page name ───────────────────────────────────
    found_page = None
    for page_bytes in PAGE_NAMES:
        if page_bytes in raw_bytes:
            found_page = page_bytes.decode("ascii")
            print(found_page)       # PC app listens for "page_<n>" on stdin
            on_page_load(found_page)
            break  # only one page name can be active at a time

    # ── 2. Scan for port_XXXX anywhere in the same chunk ─────────────────────
    # The Nextion portscan page prints "port_<number>" in the same chunk as the
    # page name, so we must keep scanning even after finding the page above.
    if "port_" in text:
        try:
            idx = text.index("port_") + 5
            port_str = ""
            while idx < len(text) and text[idx].isdigit():
                port_str += text[idx]
                idx += 1
            if port_str:
                print("portscan_init {}".format(port_str))
                return
        except Exception:
            pass

    # ── 3. Debug fallback: print unrecognised messages ────────────────────────
    if not found_page:
        try:
            print("[NEX_MSG]", text)
        except Exception:
            pass


# ── Boot sequence ─────────────────────────────────────────────────────────────

def run_connection_setup():
    """
    Initialise the Nextion display and notify the PC that the Pico is ready.

    Called once at boot. The delay gives the Nextion time to finish its own
    startup sequence before we write to it.
    """
    time.sleep(BOOT_DELAY_S)
    send_to_nextion("page main")
    send_to_nextion('pi_status.txt="Connected"')
    send_to_nextion("pi_status.pco=11648")   # NX_GREEN
    send_to_nextion("pi_con.val=1")
    print("[PICO] Initial setup complete")
    print("page_main")  # tells the PC app which page is currently active

run_connection_setup()


# ── Main loop ─────────────────────────────────────────────────────────────────

while True:
    # ── PC → Nextion (USB CDC input) ──────────────────────────────────────────
    # Read one newline-terminated command from the PC and forward it to the Nextion.
    # Commands matching DASHBOARD_PREFIXES require a page switch to main first
    # so they land on the correct elements.
    try:
        if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
            line = sys.stdin.readline()
            if line:
                cmd = line.strip()
                if cmd:
                    if cmd.startswith(DASHBOARD_PREFIXES):
                        send_to_nextion("page main")
                        time.sleep(0.05)  # give Nextion time to load the page
                    send_to_nextion(cmd)
                    print("[PC_CMD] {}".format(cmd))  # echo back so the PC can log it
    except Exception as e:
        print("[ERROR] USB read failed: {}".format(e))

    # ── Nextion → PC (UART input) ─────────────────────────────────────────────
    # Forward any print output from the Nextion to the PC via USB.
    if nextion.any():
        msg = nextion.read()
        if msg:
            handle_nextion_message(msg)

    time.sleep(0.005)  # short yield to avoid starving other Pico tasks