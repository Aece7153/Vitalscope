# pages.py
# Page refresh logic for each Nextion screen.
# (Mixin for NextionControlStation — see app.py)
# Implemented as a mixin class — NextionControlStation inherits from this.
#
# Adding a new page:
#   1. Add a method  page_<name>_refresh(self)  below.
#   2. Add its entry to PAGE_REFRESH_MAP in config.py.
#   3. Add the page name to PAGE_NAMES in pico_bridge.py.

import threading
import time

from config import (
    NX_GREEN, NX_RED, NX_YELLOW, NX_BLACK,
    PING_HOST, PING_INTERVAL, QUALITY_GAUGE,
    PROCS_REFRESH_INTERVAL,
)
from network_utils import (
    check_internet, get_dns_servers, get_speed_mbps,
    count_local_devices, check_port, get_network_quality,
)
from security_scan import scan_firewall, scan_processes
from ai_analysis import (
    _score_process,
    EXPECTED_PORT_OWNERS,
    _SUSPICIOUS_PORT_PROCESSES,
    _REGISTERED_PORT_MIN,
    _EPHEMERAL_PORT_MIN,
)


class PageHandlersMixin:
    """
    Mixin that provides per-page refresh methods for NextionControlStation.

    Each public method named page_<name>_refresh() is the entry point called
    by _on_page_change() when the Nextion switches to that page.
    """

    # ─────────────────────────────────────────────────────────────────────────
    #  PAGE: DASHBOARD
    # ─────────────────────────────────────────────────────────────────────────

    def page_dashboard_refresh(self):
        """Push all static dashboard data then start the live CPU/RAM/Disk loop."""
        self._queue_log("  [dashboard] refreshing...", "dim")
        self.send_cpu()
        self.send_ram()
        self.send_disk()
        self.send_pc_name()
        self.send_ip()
        self.send('pc_status.txt="Connected"')
        self.send(f"pc_status.pco={NX_GREEN}")
        self.send('pi_status.txt="Connected"')
        self.send(f"pi_status.pco={NX_GREEN}")
        self._start_dash_loop()  # begin 3-second CPU/RAM/Disk live update

    # ─────────────────────────────────────────────────────────────────────────
    #  PAGE: NETWORK
    # ─────────────────────────────────────────────────────────────────────────

    def page_network_refresh(self):
        """Kick off the full network refresh in a background thread."""
        self._queue_log("  [network] starting refresh...", "net")
        threading.Thread(target=self._network_full_refresh, daemon=True).start()

    def _network_full_refresh(self):
        """
        Runs in a background thread.

        Order of operations:
          1. Internet connectivity check
          2. DNS server lookup
          3. LAN device count
          4. Download / upload speed test  (slowest step)
          5. Start the quality monitor loop
        """
        # ── 1. Internet status ────────────────────────────────────────────────
        online = check_internet()
        if online:
            self.send('int_status.txt="Connected"')
            self.send(f"int_status.pco={NX_GREEN}")
            self._queue_log("  [network] internet: online", "ok")
        else:
            self.send('int_status.txt="No Internet"')
            self.send(f"int_status.pco={NX_RED}")
            self._queue_log("  [network] internet: offline", "error")

        # ── 2. DNS server ─────────────────────────────────────────────────────
        dns = get_dns_servers()
        self.send(f't_DNS.txt="{dns}"')
        self._queue_log(f"  [network] DNS: {dns}", "dim")

        # ── 3. Active device count ────────────────────────────────────────────
        dev = count_local_devices()
        self.send(f't_dev.txt="{dev} devices"')
        self._queue_log(f"  [network] devices: {dev}", "dim")

        # ── 4. Speed test ─────────────────────────────────────────────────────
        self.send('dwnld_status.txt="Measuring..."')
        self.send('upld_status.txt="Measuring..."')
        self._queue_log("  [network] measuring throughput...", "dim")

        # Pass a stop flag so the download aborts if the user leaves the page
        dl, ul = get_speed_mbps(stop_flag=lambda: self._current_page != "network")

        if self._current_page != "network":
            self._queue_log("  [network] speed test aborted — page changed", "dim")
            return

        self.send(f'dwnld_status.txt="{dl} Mbps"')
        self.send(f'upld_status.txt="{ul} Mbps"')
        self._queue_log(f"  [network] dl={dl}  ul={ul} Mbps", "net")

        # ── 5. Start quality monitor loop ─────────────────────────────────────
        self._start_net_loop()

    # ── Network quality loop management ──────────────────────────────────────

    def _start_net_loop(self):
        """Start the background quality polling loop (no-op if already running)."""
        if self._current_page != "network" or self._net_running:
            return
        self._net_stop_event.clear()
        self._net_running = True
        self._net_thread  = threading.Thread(
            target=self._net_quality_loop, daemon=True
        )
        self._net_thread.start()
        self._queue_log("  [network] quality monitor started", "dim")

    def _stop_net_loop(self):
        """Signal the quality loop to stop. Returns immediately (non-blocking)."""
        self._net_stop_event.set()
        self._net_running = False

    def _net_quality_loop(self):
        """
        Polls network quality every PING_INTERVAL seconds.

        Updates on the Nextion:
          j0.val  — quality score (0–100)
          j0.pco  — gauge colour (green / yellow / red)
          t5.txt  — score as text
          t3.txt  — average latency in ms
          t7.txt  — packet-loss percentage

        Stops immediately when _net_stop_event is set (e.g. on any page change).
        """
        self._queue_log("  [network] quality loop running", "dim")

        while not self._net_stop_event.is_set():
            score, avg_ms, loss_pct = get_network_quality()

            if self._net_stop_event.is_set():
                break  # re-check after the potentially-slow probe returns

            if score >= 75:
                color, label = NX_GREEN,  "Good"
            elif score >= 40:
                color, label = NX_YELLOW, "Fair"
            else:
                color, label = NX_RED,    "Poor"

            self.send(f"{QUALITY_GAUGE}.val={score}")
            self.send(f"{QUALITY_GAUGE}.pco={color}")

            ms_str = f"{avg_ms:.0f}" if avg_ms is not None else "---"
            self.send(f't5.txt="{score}"')
            self.send(f't3.txt="{ms_str}ms"')
            self.send(f't7.txt="{loss_pct}%"')

            self._queue_log(
                f"  [quality] {score}/100  {ms_str}ms  loss={loss_pct}%  [{label}]",
                "net",
            )

            # Interruptible sleep — wakes immediately if stop is signalled
            self._net_stop_event.wait(timeout=PING_INTERVAL)

        self._net_running = False
        self._queue_log("  [network] quality monitor stopped", "dim")

    # ─────────────────────────────────────────────────────────────────────────
    #  PAGE: PORTSCAN
    # ─────────────────────────────────────────────────────────────────────────

    # Ranked label elements — receive "PORT  process_name" in risk score order.
    PORTSCAN_ELEMENTS = ["t2", "t5", "t6", "t7", "t8", "t14", "t16"]

    # Parallel score elements — receive the bare numeric risk score for the same rank.
    PORTSCAN_SCORE_ELEMENTS = ["t21", "t22", "t25", "t80", "t443", "t53", "t3389"]

    # Per-port base risk scores (0–100).
    # These reflect the intrinsic danger of a port being open, independent of
    # which process owns it.  Process context is applied as a boost below.
    PORT_RISK_SCORES = {
        21:   85,   # FTP  — cleartext credentials, widely exploited
        22:   70,   # SSH  — brute-force target
        23:   95,   # Telnet — cleartext, essentially never legitimate
        25:   80,   # SMTP — open relay abuse
        53:   60,   # DNS  — amplification vector if misconfigured
        80:   45,   # HTTP — unencrypted, common
        135:  75,   # RPC  — lateral movement vector
        139:  78,   # NetBIOS — legacy, should be closed
        443:  20,   # HTTPS — generally fine
        445:  92,   # SMB  — ransomware / EternalBlue
        1433: 82,   # MSSQL — database exposure
        3306: 80,   # MySQL — database exposure
        3389: 90,   # RDP  — brute-force / BlueKeep
        5985: 72,   # WinRM HTTP
        5986: 68,   # WinRM HTTPS
        8080: 50,   # HTTP alt — often a forgotten dev server
        8443: 35,   # HTTPS alt
    }

    HIGH_RISK_PORTS = frozenset(PORT_RISK_SCORES.keys())

    def _port_risk_score(self, port: int, process: str = "") -> int:
        """
        Return a 0–100 risk score for a port, incorporating:

          1. Base score — per-port intrinsic risk from PORT_RISK_SCORES.
          2. Port range defaults — for ports not in the table:
               >= 49152  ephemeral/dynamic range    → base 10  (low risk)
               1024–49151 registered range          → base 25  (moderate scrutiny)
               < 1024     well-known, unrecognised  → base 40  (elevated concern)
          3. Process-context boost:
               shell / LOLBin owns the port         → +35 (always a red flag)
               known port with wrong process owner  → +25 (unexpected binding)
        """
        proc_lower = process.lower() if process else ""

        # ── Process-context boost ────────────────────────────────────────────
        proc_boost = 0
        if proc_lower in _SUSPICIOUS_PORT_PROCESSES:
            # Shell/scripting engine listening on any port is a major red flag
            proc_boost = 35
        elif port in EXPECTED_PORT_OWNERS and proc_lower:
            expected = EXPECTED_PORT_OWNERS[port]
            if proc_lower not in expected and proc_lower != "unknown":
                # Known port, but the wrong process is owning it
                proc_boost = 25

        # ── Base score ───────────────────────────────────────────────────────
        base = self.PORT_RISK_SCORES.get(port)
        if base is not None:
            return min(100, base + proc_boost)

        # Port not in the known table — use range-based default
        if port >= _EPHEMERAL_PORT_MIN:
            base = 10   # dynamic/private range — low risk by design
        elif port >= _REGISTERED_PORT_MIN:
            base = 25   # registered range — warrants scrutiny
        else:
            base = 40   # well-known range, unrecognised service

        return min(100, base + proc_boost)

    def page_portscan_refresh(self):
        """Kick off the dynamic portscan in a background thread."""
        self._queue_log("  [portscan] starting dynamic scan...", "dim")
        threading.Thread(target=self._run_portscan, daemon=True).start()

    def _run_portscan(self):
        """
        Background worker for the portscan page.

        Scores every listening port using PORT_RISK_SCORES, sorts by score
        descending, and writes the top 7 to two parallel element lists:

            PORTSCAN_ELEMENTS       (t2…t16)  — "PORT  process_name"
            PORTSCAN_SCORE_ELEMENTS (t21…t3389) — bare risk score integer

        Unused slots in both lists are cleared.
        """
        self._queue_log("  [portscan] running firewall scan...", "dim")
        fw_data = scan_firewall()

        if fw_data.get("error"):
            self._queue_log(f"  [portscan] scan error: {fw_data['error']}", "error")
            self.send('t2.txt="Scan error"')
            return

        listeners = fw_data.get("listeners", [])
        if not listeners:
            self._queue_log("  [portscan] no listening ports found", "dim")
            self.send('t2.txt="No ports found"')
            for el in self.PORTSCAN_ELEMENTS[1:] + self.PORTSCAN_SCORE_ELEMENTS:
                self.send(f'{el}.txt=""')
            return

        # Score and sort highest risk first — process name feeds into scoring
        scored = sorted(
            listeners,
            key=lambda e: self._port_risk_score(e["port"], e.get("process", "")),
            reverse=True,
        )
        top7 = scored[:len(self.PORTSCAN_ELEMENTS)]

        for label_el, score_el, entry in zip(
            self.PORTSCAN_ELEMENTS, self.PORTSCAN_SCORE_ELEMENTS, top7
        ):
            port    = entry["port"]
            process = entry.get("process") or "Unknown"
            score   = self._port_risk_score(port, process)

            if len(process) > 14:
                process = process[:13] + "~"

            label = f"{port}  {process}"
            self.send(f'{label_el}.txt="{label}"')
            self.send(f'{score_el}.txt="{score}"')
            self._queue_log(
                f'  [portscan] {label_el}="{label}"  {score_el}="{score}"', "dim"
            )

        # Clear unused slots in both lists
        for el in self.PORTSCAN_ELEMENTS[len(top7):]:
            self.send(f'{el}.txt=""')
        for el in self.PORTSCAN_SCORE_ELEMENTS[len(top7):]:
            self.send(f'{el}.txt=""')

        self._queue_log(
            f"  [portscan] done — {len(top7)} port(s) written to display", "ok"
        )

    # ─────────────────────────────────────────────────────────────────────────
    #  PAGE: PROCS   (Nextion emits "page_proc" — see PAGE_REFRESH_MAP)
    # ─────────────────────────────────────────────────────────────────────────

    # Parallel Nextion element lists — one entry per display row (4 rows total).
    # All three lists share the same rank index, so row 0 is the highest-scored
    # process, row 1 the next, and so on.
    PROCS_NAME_ELEMENTS  = ["t2",  "t9",  "t15", "t13"]
    PROCS_SCORE_ELEMENTS = ["t6",  "t10", "t16", "t12"]
    PROCS_FLAG_ELEMENTS  = ["t7",  "t8",  "t14", "t11"]

    def page_procs_refresh(self):
        """
        Run the process scan once on page-enter, then start a 2-minute
        auto-refresh loop so the displayed rows stay fresh while the user
        lingers on the page.
        """
        self._queue_log("  [procs] starting process scan...", "dim")
        threading.Thread(target=self._run_procs, daemon=True).start()
        self._start_procs_loop()

    # ── Procs auto-refresh loop ─────────────────────────────────────────────

    def _start_procs_loop(self):
        """Start the 2-minute auto-refresh loop (no-op if already running)."""
        # Guard against module-reload scenarios where attributes are missing
        if not hasattr(self, "_procs_stop_event"):
            self._procs_stop_event = threading.Event()
            self._procs_running    = False
            self._procs_thread     = None

        if self._current_page not in ("proc", "procs") or self._procs_running:
            return

        self._procs_stop_event.clear()
        self._procs_running = True
        self._procs_thread  = threading.Thread(
            target=self._procs_refresh_loop, daemon=True
        )
        self._procs_thread.start()
        self._queue_log(
            f"  [procs] auto-refresh started ({int(PROCS_REFRESH_INTERVAL)}s)",
            "dim",
        )

    def _stop_procs_loop(self):
        """Signal the procs loop to stop. Returns immediately (non-blocking)."""
        if hasattr(self, "_procs_stop_event"):
            self._procs_stop_event.set()
        self._procs_running = False

    def _procs_refresh_loop(self):
        """
        Re-run the procs scan every PROCS_REFRESH_INTERVAL seconds while the
        user is on the procs page. The initial scan is kicked off by
        page_procs_refresh(), so this loop sleeps first and then refreshes.
        """
        while not self._procs_stop_event.is_set():
            # Interruptible sleep — wakes immediately if stop is signalled
            self._procs_stop_event.wait(timeout=PROCS_REFRESH_INTERVAL)
            if self._procs_stop_event.is_set():
                break
            self._run_procs()

        self._procs_running = False
        self._queue_log("  [procs] auto-refresh stopped", "dim")

    def _run_procs(self):
        """
        Background worker: scan flagged processes, score and rank them, then
        write the top-4 highest-risk rows to the Nextion procs page.

        Uses the same scorer as the AI analysis tab so scores are consistent.
        """
        self._queue_log("  [procs] scanning processes...", "dim")
        proc_data = scan_processes()

        if proc_data.get("error"):
            self._queue_log(f"  [procs] scan error: {proc_data['error']}", "error")
            self.send('t2.txt="Scan error"')
            return

        flagged = proc_data.get("flagged", [])
        if not flagged:
            self._queue_log("  [procs] no unknown processes found", "dim")
            self.send('t2.txt="No unknown procs"')
            for el in (
                self.PROCS_NAME_ELEMENTS[1:]
                + self.PROCS_SCORE_ELEMENTS
                + self.PROCS_FLAG_ELEMENTS
            ):
                self.send(f'{el}.txt=""')
            return

        # Score and sort highest risk first
        scored = sorted(
            flagged,
            key=lambda p: _score_process(p)[0],
            reverse=True,
        )
        top4 = scored[: len(self.PROCS_NAME_ELEMENTS)]

        for name_el, score_el, flag_el, proc in zip(
            self.PROCS_NAME_ELEMENTS,
            self.PROCS_SCORE_ELEMENTS,
            self.PROCS_FLAG_ELEMENTS,
            top4,
        ):
            score, reasons = _score_process(proc)
            name = proc.get("name", "?")
            if len(name) > 14:
                name = name[:13] + "~"
            flag = reasons[0][:16] if reasons else "Unknown"
            self.send(f'{name_el}.txt="{name}"')
            self.send(f'{score_el}.txt="{score}"')
            self.send(f'{flag_el}.txt="{flag}"')
            self._queue_log(
                f'  [procs] {name_el}="{name}"  {score_el}="{score}"', "dim"
            )

        # Clear unused slots
        for el in self.PROCS_NAME_ELEMENTS[len(top4) :]:
            self.send(f'{el}.txt=""')
        for el in self.PROCS_SCORE_ELEMENTS[len(top4) :]:
            self.send(f'{el}.txt=""')
        for el in self.PROCS_FLAG_ELEMENTS[len(top4) :]:
            self.send(f'{el}.txt=""')

        self._queue_log(
            f"  [procs] done — {len(top4)} process(es) written to display", "ok"
        )

    # ────────────────────────────────────────────────────────────────────────────
    #  PAGE: LOCK
    # ────────────────────────────────────────────────────────────────────────────

    def page_lock_refresh(self):
        """
        Called when the Nextion navigates to the lock page.

        Stops any running background loops (network quality, procs auto-refresh)
        so they do not continue consuming resources while the display is locked.
        """
        self._queue_log("  [lock] page active — stopping background loops", "dim")
        self._stop_net_loop()
        self._stop_procs_loop()
