# monitor.py
# Always-on background monitor for Nextion Control Station.
#
# Runs three independent loops regardless of Nextion connection state:
#   1. ResourceMonitor  — CPU / RAM / disk, fires Discord alerts on threshold breach
#   2. ProcessMonitor   — periodic process scan + LOCAL heuristic risk scoring
#   3. SecurityMonitor  — full firewall/port scan on a longer interval
#
# Process alerts are only fired for processes whose heuristic score meets or
# exceeds the configurable PROCESS_RISK_THRESHOLD (default 60, range 0–100).
# All monitors start at app launch and run until the process exits.

import threading
import time
from collections import deque

import psutil

from discord_notifier import (
    alert_resource, alert_high_risk_process, alert_security_summary,
)
from security_scan import scan_processes, scan_firewall
from heuristic import score_all
from config import (
    CPU_ALERT_THRESHOLD, RAM_ALERT_THRESHOLD, DISK_ALERT_THRESHOLD,
    PROCESS_RISK_THRESHOLD,
    RESOURCE_POLL_INTERVAL, PROCESS_SCAN_INTERVAL, SECURITY_SCAN_INTERVAL,
    HIGH_RISK_PORTS_SET,
)


# ── Resource Monitor ──────────────────────────────────────────────────────────

class ResourceMonitor:
    """
    Polls CPU, RAM, and disk on a fixed interval.

    Callbacks:
        on_update(cpu, ram, disk)  — called every poll with latest percentages
        on_alert(resource, value)  — called when a threshold is breached
    """

    def __init__(
        self,
        webhook_url_fn,
        on_update=None,
        on_alert=None,
        poll_interval=RESOURCE_POLL_INTERVAL,
        cpu_threshold=CPU_ALERT_THRESHOLD,
        ram_threshold=RAM_ALERT_THRESHOLD,
        disk_threshold=DISK_ALERT_THRESHOLD,
    ):
        self._webhook_url_fn = webhook_url_fn
        self._on_update      = on_update
        self._on_alert       = on_alert
        self._poll_interval  = poll_interval
        self._cpu_threshold  = cpu_threshold
        self._ram_threshold  = ram_threshold
        self._disk_threshold = disk_threshold

        self._cpu_history = deque(maxlen=5)
        self._stop        = threading.Event()
        self._thread      = threading.Thread(
            target=self._run, daemon=True, name="ResourceMonitor"
        )

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()

    def set_thresholds(self, cpu=None, ram=None, disk=None):
        if cpu  is not None: self._cpu_threshold  = cpu
        if ram  is not None: self._ram_threshold  = ram
        if disk is not None: self._disk_threshold = disk

    def _run(self):
        while not self._stop.is_set():
            try:
                self._cpu_history.append(psutil.cpu_percent(interval=0.5))
                cpu  = round(sum(self._cpu_history) / len(self._cpu_history), 1)
                ram  = psutil.virtual_memory().percent
                disk = psutil.disk_usage("/").percent

                if self._on_update:
                    self._on_update(cpu, ram, disk)

                url = self._webhook_url_fn()

                if cpu >= self._cpu_threshold:
                    if self._on_alert: self._on_alert("CPU", cpu)
                    alert_resource(url, "CPU", cpu, self._cpu_threshold)

                if ram >= self._ram_threshold:
                    if self._on_alert: self._on_alert("RAM", ram)
                    alert_resource(url, "RAM", ram, self._ram_threshold)

                if disk >= self._disk_threshold:
                    if self._on_alert: self._on_alert("Disk", disk)
                    alert_resource(url, "Disk", disk, self._disk_threshold)

            except Exception:
                pass

            self._stop.wait(timeout=self._poll_interval)


# ── Process Monitor ───────────────────────────────────────────────────────────

class ProcessMonitor:
    """
    Periodically scans running processes, runs every flagged process through
    the local heuristic scorer, and only alerts on processes that score at or
    above the configurable risk threshold.

    Each unique PID is scored once per session — subsequent scans where the
    same PID is still running will not re-alert.

    Callbacks:
        on_scan_complete(scored_high_risk, total_running)
            scored_high_risk — list of proc dicts that met the threshold,
                               each augmented with {"score", "risk", "reasons"}
            total_running    — total process count from this scan

        on_high_risk_process(proc_with_score)
            Called once per newly-seen PID that scored above the threshold.
    """

    def __init__(
        self,
        webhook_url_fn,
        risk_threshold_fn=None,       # callable() → int  (live value from UI)
        on_scan_complete=None,
        on_high_risk_process=None,
        scan_interval=PROCESS_SCAN_INTERVAL,
    ):
        self._webhook_url_fn      = webhook_url_fn
        self._risk_threshold_fn   = risk_threshold_fn or (lambda: PROCESS_RISK_THRESHOLD)
        self._on_scan_complete    = on_scan_complete
        self._on_high_risk_process = on_high_risk_process
        self._scan_interval       = scan_interval

        self._seen_pids = set()   # PIDs already reported this session
        self._stop      = threading.Event()
        self._thread    = threading.Thread(
            target=self._run, daemon=True, name="ProcessMonitor"
        )

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        # Short startup delay so the UI is fully ready before the first scan
        self._stop.wait(timeout=5.0)
        while not self._stop.is_set():
            try:
                self._do_scan()
            except Exception:
                pass
            self._stop.wait(timeout=self._scan_interval)

    def _do_scan(self):
        threshold = int(self._risk_threshold_fn())

        raw = scan_processes()
        flagged = raw.get("flagged", [])
        total   = raw.get("total", 0)

        # Score all whitelist-unknown processes and filter to those >= threshold
        high_risk = score_all(flagged, threshold=threshold)

        if self._on_scan_complete:
            self._on_scan_complete(high_risk, total)

        url = self._webhook_url_fn()

        for proc in high_risk:
            pid = proc.get("pid", 0)
            if pid in self._seen_pids:
                continue
            self._seen_pids.add(pid)

            if self._on_high_risk_process:
                self._on_high_risk_process(proc)

            alert_high_risk_process(url, proc)


# ── Security Monitor ──────────────────────────────────────────────────────────

class SecurityMonitor:
    """
    Runs a full firewall/port scan on a longer interval (default 10 minutes).

    Callbacks:
        on_scan_complete(firewall_data)  — called after every scan
    """

    HIGH_RISK_PORTS = HIGH_RISK_PORTS_SET

    def __init__(
        self,
        webhook_url_fn,
        risk_threshold_fn=None,
        on_scan_complete=None,
        scan_interval=SECURITY_SCAN_INTERVAL,
    ):
        self._webhook_url_fn   = webhook_url_fn
        self._risk_threshold_fn = risk_threshold_fn or (lambda: PROCESS_RISK_THRESHOLD)
        self._on_scan_complete = on_scan_complete
        self._scan_interval    = scan_interval

        self._stop   = threading.Event()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="SecurityMonitor"
        )

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        self._stop.wait(timeout=30.0)
        while not self._stop.is_set():
            try:
                self._do_scan()
            except Exception:
                pass
            self._stop.wait(timeout=self._scan_interval)

    def _do_scan(self):
        fw_data = scan_firewall()

        if self._on_scan_complete:
            self._on_scan_complete(fw_data)

        if fw_data.get("error"):
            return

        listeners   = fw_data.get("listeners", [])
        risky_ports = [l["port"] for l in listeners if l["port"] in self.HIGH_RISK_PORTS]
        open_ports  = len(listeners)

        # Use heuristic scorer to count how many unknown procs are actually high-risk
        threshold = int(self._risk_threshold_fn())
        raw       = scan_processes()
        high_risk = score_all(raw.get("flagged", []), threshold=threshold)

        alert_security_summary(
            self._webhook_url_fn(),
            len(high_risk),
            risky_ports,
            open_ports,
        )


# ── Convenience bundle ────────────────────────────────────────────────────────

class SystemMonitor:
    """
    Owns and manages all three monitor instances.

    Usage:
        monitor = SystemMonitor(
            webhook_url_fn=lambda: app.webhook_var.get(),
            risk_threshold_fn=lambda: int(app.proc_thresh_var.get()),
            ...
        )
        monitor.start()
    """

    def __init__(
        self,
        webhook_url_fn,
        risk_threshold_fn=None,
        on_resource_update=None,
        on_resource_alert=None,
        on_process_scan=None,
        on_high_risk_process=None,
        on_security_scan=None,
    ):
        self.resource = ResourceMonitor(
            webhook_url_fn,
            on_update=on_resource_update,
            on_alert=on_resource_alert,
        )
        self.process = ProcessMonitor(
            webhook_url_fn,
            risk_threshold_fn=risk_threshold_fn,
            on_scan_complete=on_process_scan,
            on_high_risk_process=on_high_risk_process,
        )
        self.security = SecurityMonitor(
            webhook_url_fn,
            risk_threshold_fn=risk_threshold_fn,
            on_scan_complete=on_security_scan,
        )

    def start(self):
        self.resource.start()
        self.process.start()
        self.security.start()

    def stop(self):
        self.resource.stop()
        self.process.stop()
        self.security.stop()

    def set_thresholds(self, cpu=None, ram=None, disk=None):
        self.resource.set_thresholds(cpu=cpu, ram=ram, disk=disk)