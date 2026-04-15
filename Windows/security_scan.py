# security_scan.py
# Windows local-machine security scanner for Nextion Control Station.
#
# Collects three categories of data:
#   1. Suspicious processes  — flags unknown/unsigned executables
#   2. User accounts         — local accounts with last-login timestamps
#   3. Firewall & network    — firewall state, rule counts, adapters,
#                              listening ports with bound service names
#
# All scan functions return plain dicts so they are easy to log, display,
# or forward to the Nextion. The GUI (SecurityScanWindow) is a Toplevel
# tk.Frame that can be packed into any parent widget.
#
# Usage (standalone):
#   python security_scan.py
#
# Usage (embedded in NextionControlStation):
#   from security_scan import SecurityScanWindow
#   SecurityScanWindow(parent)

import os
import subprocess
import re
import time
import socket
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import psutil
from datetime import datetime

from config import (
    BG, BG2, BG3, BORDER,
    ACCENT, ACCENT2, GREEN, RED, YELLOW,
    TEXT, TEXT_DIM, TEXT_HEAD,
    FONT_MONO, FONT_MONO_SM, FONT_LABEL, FONT_HEAD, FONT_TITLE,
    NX_GREEN, NX_RED, NX_YELLOW,
)
from ui_widgets import styled_btn
from ai_analysis import analyse as ai_analyse


# ── Known-safe process whitelist ───────────────────────────────────────────────
# Process names here (lowercase, filename only, no path) are considered trusted.
# Anything NOT in this set gets flagged as "unknown" — not necessarily malicious,
# but worth a manual review. Add your own regularly-used apps as needed.

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


# ── Scan functions (no GUI dependencies) ──────────────────────────────────────

def scan_processes():
    """
    Enumerate running processes and flag any not in KNOWN_SAFE_PROCESSES.

    Uses 'tasklist /FO CSV /NH' for names and memory, then cross-references
    psutil to resolve the full executable path for each flagged PID.

    Returns:
        {
          "flagged": [
            {
              "name":   str,
              "pid":    int,
              "mem_kb": int,
              "path":   str|None,
            }, ...
          ],
          "total": int,
          "error": str|None
        }
    """
    try:
        result = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=15,
        )
        flagged = []
        total   = 0

        # Build a pid→path map from psutil in one pass (faster than per-PID lookups)
        pid_path_map = {}
        for proc in psutil.process_iter(["pid", "exe"]):
            try:
                pid_path_map[proc.info["pid"]] = proc.info["exe"]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        for line in result.stdout.strip().splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) < 5:
                continue
            total += 1
            name   = parts[0].lower()
            pid    = int(parts[1]) if parts[1].isdigit() else 0
            mem_kb = int(re.sub(r"[^\d]", "", parts[4])) if parts[4] else 0

            if name not in KNOWN_SAFE_PROCESSES:
                flagged.append({
                    "name":   parts[0],
                    "pid":    pid,
                    "mem_kb": mem_kb,
                    "path":   pid_path_map.get(pid),
                })

        return {"flagged": flagged, "total": total, "error": None}

    except Exception as e:
        return {"flagged": [], "total": 0, "error": str(e)}


def scan_users():
    """
    List all local user accounts with last-login timestamps and admin status.

    Uses 'net user' to enumerate names, then 'net user <n>' per account for
    details, and 'net localgroup Administrators' to identify admin accounts.

    Returns:
        {
          "accounts": [
            {
              "name":       str,
              "last_login": str,    # "Never" or a Windows date/time string
              "is_admin":   bool,
              "active":     bool,
            }, ...
          ],
          "error": str|None
        }
    """
    try:
        result   = subprocess.run(
            ["net", "user"], capture_output=True, text=True, timeout=10
        )
        names    = []
        in_names = False
        for line in result.stdout.splitlines():
            if line.startswith("---"):
                in_names = True
                continue
            if not in_names:
                continue
            stripped = line.strip()
            if not stripped:
                continue
            # The footer "The command completed successfully." marks the end of
            # the account list — stop here so we never parse prose as names.
            if stripped.lower().startswith("the command"):
                break
            # Each token must look like a valid Windows username:
            # 1–20 chars, only letters, digits, hyphens, underscores, dots.
            for token in stripped.split():
                if re.fullmatch(r"[\w.\-]{1,20}", token):
                    names.append(token)

        # Build the set of admin usernames (lowercase for case-insensitive match)
        admin_result = subprocess.run(
            ["net", "localgroup", "Administrators"],
            capture_output=True, text=True, timeout=10,
        )
        admin_names = set(
            re.findall(r"^(\S+)$", admin_result.stdout.lower(), re.MULTILINE)
        )

        accounts = []
        for name in names:
            try:
                detail = subprocess.run(
                    ["net", "user", name],
                    capture_output=True, text=True, timeout=8,
                )
                text = detail.stdout

                login_match = re.search(r"Last logon\s+(.*)", text)
                last_login  = login_match.group(1).strip() if login_match else "Never"
                if last_login.lower() in ("never", "none", ""):
                    last_login = "Never"

                active_match = re.search(r"Account active\s+(\w+)", text)
                active       = (active_match.group(1).lower() == "yes") if active_match else True

                accounts.append({
                    "name":       name,
                    "last_login": last_login,
                    "is_admin":   name.lower() in admin_names,
                    "active":     active,
                })
            except Exception:
                continue

        return {"accounts": accounts, "error": None}

    except Exception as e:
        return {"accounts": [], "error": str(e)}


def scan_firewall():
    """
    Collect Windows firewall profile states, rule counts, adapters, and listeners.

    Commands used:
        netsh advfirewall show allprofiles      — per-profile ON/OFF state
        netsh advfirewall firewall show rule    — enumerate rules for counting
        ipconfig /all                           — adapter names, IPs, MACs
        netstat -ano                            — LISTENING sockets with PIDs
        tasklist /FO CSV /NH                    — PID → process name map

    Returns:
        {
          "profiles":  {"Domain": {"state": "ON"|"OFF"}, ...},
          "rules":     {"inbound": int, "outbound": int},
          "adapters":  [{"name": str, "ip": str, "mac": str}, ...],
          "listeners": [{"port": int, "proto": str, "pid": int, "process": str}, ...],
          "error":     str|None
        }
    """
    try:
        result = {}

        # ── Firewall profile states ───────────────────────────────────────────
        fw = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles"],
            capture_output=True, text=True, timeout=10,
        )
        profiles     = {}
        current_prof = None
        for line in fw.stdout.splitlines():
            prof_match  = re.match(r"^(\w+)\s+Profile Settings", line)
            state_match = re.search(r"State\s+(ON|OFF)", line, re.IGNORECASE)
            if prof_match:
                current_prof = prof_match.group(1)
            elif state_match and current_prof:
                profiles[current_prof] = {"state": state_match.group(1).upper()}
        result["profiles"] = profiles

        # ── Inbound / outbound rule counts ────────────────────────────────────
        in_rules = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all", "dir=in"],
            capture_output=True, text=True, timeout=15,
        )
        out_rules = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all", "dir=out"],
            capture_output=True, text=True, timeout=15,
        )
        result["rules"] = {
            "inbound":  len(re.findall(r"^Rule Name:", in_rules.stdout,  re.MULTILINE)),
            "outbound": len(re.findall(r"^Rule Name:", out_rules.stdout, re.MULTILINE)),
        }

        # ── Network adapters (IPv4 only) ──────────────────────────────────────
        ipcfg = subprocess.run(
            ["ipconfig", "/all"], capture_output=True, text=True, timeout=10
        )
        adapters     = []
        current_name = None
        current_ip   = None
        current_mac  = None

        for line in ipcfg.stdout.splitlines():
            adapter_match = re.match(r"^(\S.*):$", line)
            ip_match      = re.search(r"IPv4 Address.*?:\s*([\d.]+)", line)
            mac_match     = re.search(r"Physical Address.*?:\s*([\w-]+)", line)

            if adapter_match:
                if current_name and current_ip:
                    adapters.append({
                        "name": current_name,
                        "ip":   current_ip,
                        "mac":  current_mac or "N/A",
                    })
                current_name = adapter_match.group(1).strip()
                current_ip   = None
                current_mac  = None
            elif ip_match:
                current_ip  = ip_match.group(1)
            elif mac_match:
                current_mac = mac_match.group(1)

        if current_name and current_ip:
            adapters.append({"name": current_name, "ip": current_ip, "mac": current_mac or "N/A"})
        result["adapters"] = adapters

        # ── Listening ports ───────────────────────────────────────────────────
        tl = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=10,
        )
        pid_map = {}
        for line in tl.stdout.strip().splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 2 and parts[1].isdigit():
                pid_map[int(parts[1])] = parts[0]

        ns = subprocess.run(
            ["netstat", "-ano"], capture_output=True, text=True, timeout=15
        )
        listeners = []
        seen      = set()
        for line in ns.stdout.splitlines():
            m = re.match(
                r"\s*(TCP|UDP)\s+[\d.:]+:(\d+)\s+[\d.:*]+\s+LISTENING\s+(\d+)",
                line, re.IGNORECASE,
            )
            if m:
                proto, port, pid = m.group(1).upper(), int(m.group(2)), int(m.group(3))
                key = (proto, port)
                if key not in seen:
                    seen.add(key)
                    listeners.append({
                        "port":    port,
                        "proto":   proto,
                        "pid":     pid,
                        "process": pid_map.get(pid, "Unknown"),
                    })

        result["listeners"] = sorted(listeners, key=lambda x: x["port"])
        result["error"]     = None
        return result

    except Exception as e:
        return {
            "profiles":  {},
            "rules":     {"inbound": 0, "outbound": 0},
            "adapters":  [],
            "listeners": [],
            "error":     str(e),
        }


def run_full_scan():
    """
    Execute all three scan functions and return a combined results dict.

    Returns:
        {
          "timestamp": str,    # ISO-format datetime of scan start
          "processes": dict,   # from scan_processes()
          "users":     dict,   # from scan_users()
          "firewall":  dict,   # from scan_firewall()
        }
    """
    return {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "processes": scan_processes(),
        "users":     scan_users(),
        "firewall":  scan_firewall(),
    }


# ── GUI ────────────────────────────────────────────────────────────────────────

class SecurityScanWindow:
    """
    Drop-in Tkinter security scan panel styled to match NextionControlStation.

    Contains a tabbed results view (Processes / Users / Firewall & Network)
    with colour-coded risk indicators, a scan button, and an animated status bar.

    Optionally pushes a compact summary to the Nextion display via send_fn.

    Args:
        parent:  Tkinter parent widget to attach this panel to
        send_fn: optional callable(cmd: str) — forwards summary lines to Nextion
    """

    HIGH_RISK_PORTS = frozenset({21, 23, 135, 137, 138, 139, 445, 1433, 3306, 3389, 5985})

    def __init__(self, parent, send_fn=None):
        self.send_fn    = send_fn
        self._scanning  = False
        self._last_scan = None

        self.win = tk.Toplevel(parent)
        self.win.title("Security Scan — Nextion Control Station")
        self.win.geometry("1000x680")
        self.win.minsize(720, 480)
        self.win.configure(bg=BG)
        self.win.resizable(True, True)

        self.frame = tk.Frame(self.win, bg=BG)
        self.frame.pack(fill="both", expand=True)

        self._proc_sort_col = None
        self._proc_sort_asc = True
        self._ai_streaming  = False

        self._build_header()
        self._build_results_area()
        self._build_status_bar()
        self._apply_tree_style()

    # ── Layout builders ───────────────────────────────────────────────────────

    def _build_header(self):
        """Red-accented title bar with scan button and last-scan timestamp."""
        hdr = tk.Frame(self.frame, bg=BG3, height=44)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(
            hdr, text="  SECURITY SCAN",
            bg=BG3, fg=RED, font=FONT_TITLE, padx=16,
        ).pack(side="left", pady=8)

        self.last_scan_var = tk.StringVar(value="Never scanned")
        tk.Label(
            hdr, textvariable=self.last_scan_var,
            bg=BG3, fg=TEXT_DIM, font=FONT_MONO_SM,
        ).pack(side="right", padx=12)

        self.scan_btn = styled_btn(
            hdr, "[ RUN SCAN ]", self._start_scan, color=RED, width=14
        )
        self.scan_btn.pack(side="right", padx=(0, 8), pady=8)

        tk.Frame(self.frame, bg=RED, height=1).pack(fill="x")

    def _build_results_area(self):
        """Tabbed notebook with one tab per scan category."""
        style = ttk.Style()
        style.configure("Scan.TNotebook", background=BG, tabmargins=[2, 4, 0, 0])
        style.configure(
            "Scan.TNotebook.Tab",
            background=BG3, foreground=TEXT_DIM, font=FONT_LABEL, padding=[12, 4],
        )
        style.map(
            "Scan.TNotebook.Tab",
            background=[("selected", BG2)],
            foreground=[("selected", RED)],
        )

        self.notebook = ttk.Notebook(self.frame, style="Scan.TNotebook")
        self.notebook.pack(fill="both", expand=True, padx=8, pady=8)

        # ── Processes tab ─────────────────────────────────────────────────────
        proc_tab = tk.Frame(self.notebook, bg=BG2)
        self.notebook.add(proc_tab, text="  PROCESSES  ")

        self.proc_summary = tk.Label(
            proc_tab, text="Run a scan to see results.",
            bg=BG2, fg=TEXT_DIM, font=FONT_MONO_SM, anchor="w", padx=8, pady=4,
        )
        self.proc_summary.pack(fill="x")
        tk.Frame(proc_tab, bg=BORDER, height=1).pack(fill="x")

        self.proc_tree = self._make_tree(
            proc_tab,
            columns=("name", "pid", "mem", "flag", "path"),
            headings=("Process Name", "PID", "Memory", "Flag", "Executable Path"),
            widths=(180, 60, 80, 160, 340),
        )

        for col in ("mem", "flag"):
            self.proc_tree.heading(col, command=lambda c=col: self._sort_proc_tree(c))

        # Right-click context menu for process rows
        self._proc_context_menu = tk.Menu(
            self.win, tearoff=0,
            bg=BG3, fg=TEXT, activebackground=ACCENT, activeforeground=BG,
            font=FONT_MONO_SM, bd=0, relief="flat",
        )
        self._proc_context_menu.add_command(
            label="  Open file location",
            command=self._open_selected_proc_location,
        )
        self._proc_context_menu.add_command(
            label="  Copy path to clipboard",
            command=self._copy_selected_proc_path,
        )
        self.proc_tree.bind("<Button-3>", self._show_proc_context_menu)

        # ── Users tab ─────────────────────────────────────────────────────────
        user_tab = tk.Frame(self.notebook, bg=BG2)
        self.notebook.add(user_tab, text="  USERS  ")

        self.user_summary = tk.Label(
            user_tab, text="Run a scan to see results.",
            bg=BG2, fg=TEXT_DIM, font=FONT_MONO_SM, anchor="w", padx=8, pady=4,
        )
        self.user_summary.pack(fill="x")
        tk.Frame(user_tab, bg=BORDER, height=1).pack(fill="x")

        self.user_tree = self._make_tree(
            user_tab,
            columns=("name", "last_login", "admin", "active"),
            headings=("Username", "Last Login", "Admin", "Active"),
            widths=(160, 220, 70, 70),
        )

        # ── Firewall & Network tab ────────────────────────────────────────────
        fw_tab = tk.Frame(self.notebook, bg=BG2)
        self.notebook.add(fw_tab, text="  FIREWALL & NETWORK  ")

        self.fw_tree = self._make_tree(
            fw_tab,
            columns=("category", "item", "value"),
            headings=("Category", "Item", "Value / Detail"),
            widths=(140, 200, 320),
        )

        # ── AI Analysis tab ───────────────────────────────────────────────────
        ai_tab = tk.Frame(self.notebook, bg=BG2)
        self.notebook.add(ai_tab, text="  AI ANALYSIS  ")

        ai_ctrl = tk.Frame(ai_tab, bg=BG2)
        ai_ctrl.pack(fill="x", padx=8, pady=(6, 0))

        self.ai_run_btn = styled_btn(
            ai_ctrl, "[ RUN ANALYSIS ]", self._start_ai_analysis, color=ACCENT2, width=18
        )
        self.ai_run_btn.pack(side="left")

        self.ai_status_var = tk.StringVar(value="Run a scan first, then click Run Analysis.")
        tk.Label(
            ai_ctrl, textvariable=self.ai_status_var,
            bg=BG2, fg=TEXT_DIM, font=FONT_MONO_SM, anchor="w", padx=12,
        ).pack(side="left", fill="x", expand=True)

        self.ai_clear_btn = styled_btn(
            ai_ctrl, "CLEAR", self._clear_ai_output, color=TEXT_DIM, width=6
        )
        self.ai_clear_btn.pack(side="right")

        tk.Frame(ai_tab, bg=BORDER, height=1).pack(fill="x", pady=(6, 0))

        ai_text_frame = tk.Frame(ai_tab, bg=BG2)
        ai_text_frame.pack(fill="both", expand=True, padx=4, pady=4)

        ai_sb = tk.Scrollbar(ai_text_frame, bg=BG3)
        ai_sb.pack(side="right", fill="y")

        self.ai_text = tk.Text(
            ai_text_frame,
            bg=BG, fg=TEXT, insertbackground=ACCENT,
            relief="flat", bd=0, font=FONT_MONO_SM,
            state="disabled", wrap="word",
            highlightthickness=1, highlightbackground=BORDER,
            yscrollcommand=ai_sb.set,
        )
        ai_sb.config(command=self.ai_text.yview)
        self.ai_text.pack(fill="both", expand=True)

        self.ai_text.tag_config("header",   foreground=ACCENT,  font=("Consolas", 9, "bold"))
        self.ai_text.tag_config("high",     foreground=RED)
        self.ai_text.tag_config("moderate", foreground=YELLOW)
        self.ai_text.tag_config("low",      foreground=ACCENT2)
        self.ai_text.tag_config("clean",    foreground=GREEN)
        self.ai_text.tag_config("dim",      foreground=TEXT_DIM)
        self.ai_text.tag_config("normal",   foreground=TEXT)

        self.ai_text.bind(
            "<MouseWheel>",
            lambda e: self.ai_text.yview_scroll(int(-1 * (e.delta / 120)), "units"),
        )

    def _build_status_bar(self):
        """Slim bottom bar showing scan state and an animated spinner."""
        bar = tk.Frame(self.frame, bg=BG3, height=26)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self.status_var = tk.StringVar(value="Ready.")
        tk.Label(
            bar, textvariable=self.status_var,
            bg=BG3, fg=TEXT_DIM, font=FONT_MONO_SM, anchor="w", padx=10,
        ).pack(side="left", fill="y")

        self.spinner_var = tk.StringVar(value="")
        tk.Label(
            bar, textvariable=self.spinner_var,
            bg=BG3, fg=RED, font=FONT_MONO_SM, padx=10,
        ).pack(side="right", fill="y")

    def _make_tree(self, parent, columns, headings, widths):
        """
        Build a scrollable dark Treeview inside a container frame.

        Args:
            parent:   parent widget
            columns:  tuple of internal column ID strings
            headings: tuple of header label strings (same order as columns)
            widths:   tuple of pixel widths (same order as columns)

        Returns:
            The configured ttk.Treeview widget.
        """
        container = tk.Frame(parent, bg=BG2)
        container.pack(fill="both", expand=True, padx=4, pady=4)

        sb = tk.Scrollbar(container, bg=BG3)
        sb.pack(side="right", fill="y")

        tree = ttk.Treeview(
            container, columns=columns, show="headings",
            style="Scan.Treeview", yscrollcommand=sb.set,
        )
        sb.config(command=tree.yview)
        tree.pack(fill="both", expand=True)

        for col, heading, width in zip(columns, headings, widths):
            tree.heading(col, text=heading, anchor="w")
            tree.column(col, width=width, minwidth=40, anchor="w", stretch=True)

        tree.bind(
            "<MouseWheel>",
            lambda e: tree.yview_scroll(int(-1 * (e.delta / 120)), "units"),
        )
        return tree

    def _apply_tree_style(self):
        """Configure the Scan.Treeview ttk style to match the dark theme."""
        s = ttk.Style()
        s.configure(
            "Scan.Treeview",
            background=BG, foreground=TEXT, fieldbackground=BG,
            rowheight=22, font=FONT_MONO_SM, borderwidth=0,
        )
        s.configure(
            "Scan.Treeview.Heading",
            background=BG3, foreground=ACCENT, font=FONT_LABEL,
            relief="flat", borderwidth=0,
        )
        s.map(
            "Scan.Treeview",
            background=[("selected", BG3)],
            foreground=[("selected", ACCENT)],
        )

    # ── Scan lifecycle ────────────────────────────────────────────────────────

    def _start_scan(self):
        """Disable button, clear trees, and kick off the scan in a background thread."""
        if self._scanning:
            return
        self._scanning = True
        self.scan_btn.config(state="disabled", text="[ SCANNING... ]")
        self._clear_all_trees()
        self.status_var.set("Scanning — this may take 15–30 seconds...")
        self._animate_spinner()
        threading.Thread(target=self._run_and_display, daemon=True).start()

    def _run_and_display(self):
        """Run the full scan (background thread) then hand results to the main thread."""
        results = run_full_scan()
        self.frame.after(0, self._display_results, results)

    def _animate_spinner(self, tick=0):
        """Cycle a block-style spinner while a scan is in progress."""
        if not self._scanning:
            self.spinner_var.set("")
            return
        frames = ["[■□□□]", "[□■□□]", "[□□■□]", "[□□□■]"]
        self.spinner_var.set(frames[tick % len(frames)])
        self.frame.after(200, self._animate_spinner, tick + 1)

    def _clear_all_trees(self):
        """Delete every row from each Treeview before populating fresh data."""
        for tree in (self.proc_tree, self.user_tree, self.fw_tree):
            tree.delete(*tree.get_children())
        self._clear_ai_output()

    # ── Result display ────────────────────────────────────────────────────────

    def _display_results(self, results):
        """
        Populate all three tabs from the finished scan results.
        Must run on the main thread (invoked via frame.after).
        """
        self._scanning  = False
        self._last_scan = results
        self.scan_btn.config(state="normal", text="[ RUN SCAN ]")
        self.last_scan_var.set(f"Last scan: {results.get('timestamp', '')}")

        self._display_processes(results["processes"])
        self._display_users(results["users"])
        self._display_firewall(results["firewall"])

        flagged   = len(results["processes"].get("flagged", []))
        has_error = any(
            results[k].get("error") for k in ("processes", "users", "firewall")
        )
        suffix = " (some sections had errors)" if has_error else ""
        self.status_var.set(
            f"Scan complete{suffix}. {flagged} unknown process(es) flagged."
        )

        if self.send_fn:
            self._push_to_nextion(results)

        # Auto-run AI analysis after every scan
        self._start_ai_analysis()

    def _display_processes(self, data):
        """Fill the Processes tab with flagged (unknown) process rows."""
        if data.get("error"):
            self.proc_summary.config(text=f"  Error: {data['error']}", fg=RED)
            return

        flagged = data.get("flagged", [])
        total   = data.get("total", 0)
        count   = len(flagged)

        self._proc_flagged_data = flagged

        summary_color = GREEN if count <= 3 else (YELLOW if count <= 10 else RED)
        self.proc_summary.config(
            text=f"  {total} processes running  —  {count} unknown (not in whitelist)",
            fg=summary_color,
        )

        self._populate_proc_tree(flagged)

    def _populate_proc_tree(self, flagged: list):
        """
        Clear and re-fill the process treeview from a list of flagged process dicts.

        Separated from _display_processes so _sort_proc_tree() can call it
        independently after reordering the data.
        """
        self.proc_tree.delete(*self.proc_tree.get_children())

        for proc in flagged:
            mem_str  = f"{proc['mem_kb'] // 1024} MB" if proc["mem_kb"] else "N/A"
            flag_str = "Unknown + High Mem" if proc["mem_kb"] > 500_000 else "Unknown"
            tag      = "risk" if proc["mem_kb"] > 500_000 else "warn"
            path_str = proc.get("path") or "(path unavailable)"
            self.proc_tree.insert(
                "", "end",
                values=(proc["name"], proc["pid"], mem_str, flag_str, path_str),
                tags=(tag,),
            )

        self.proc_tree.tag_configure("warn", foreground=YELLOW)
        self.proc_tree.tag_configure("risk", foreground=RED)

    def _sort_proc_tree(self, col: str):
        """
        Sort the process treeview by the given column and re-render.

        Clicking the same column header a second time reverses the sort order.
        Sortable columns: "mem" (numeric) and "flag" (alphabetic, High Mem first).
        """
        if self._proc_sort_col == col:
            self._proc_sort_asc = not self._proc_sort_asc
        else:
            self._proc_sort_col = col
            self._proc_sort_asc = False  # default to highest-first on first click

        asc = self._proc_sort_asc

        if col == "mem":
            key_fn = lambda p: p.get("mem_kb") or 0
        else:
            key_fn = lambda p: (0 if p.get("mem_kb", 0) > 500_000 else 1, p.get("name", "").lower())

        data        = getattr(self, "_proc_flagged_data", [])
        sorted_data = sorted(data, key=key_fn, reverse=not asc)

        arrow = " ▲" if asc else " ▼"
        heading_labels = {
            "name": "Process Name",
            "pid":  "PID",
            "mem":  "Memory",
            "flag": "Flag",
            "path": "Executable Path",
        }
        for c, base_label in heading_labels.items():
            self.proc_tree.heading(c, text=base_label + (arrow if c == col else ""))

        self._populate_proc_tree(sorted_data)

    # ── Process context menu ──────────────────────────────────────────────────

    def _show_proc_context_menu(self, event):
        """Show the right-click context menu only when a row is actually selected."""
        row = self.proc_tree.identify_row(event.y)
        if row:
            self.proc_tree.selection_set(row)
            self._proc_context_menu.post(event.x_root, event.y_root)

    def _get_selected_proc_path(self):
        """
        Return the executable path of the currently selected process row.

        Returns None if nothing is selected or the path is unavailable.
        """
        sel = self.proc_tree.selection()
        if not sel:
            return None
        path = self.proc_tree.item(sel[0], "values")[4]
        return None if path == "(path unavailable)" else path

    def _open_selected_proc_location(self):
        """
        Open File Explorer with the selected process's executable highlighted.

        Uses 'explorer /select,<path>' to select the file in its folder.
        """
        path = self._get_selected_proc_path()
        if not path:
            messagebox.showwarning(
                "Path Unavailable",
                "The executable path for this process could not be resolved.\n"
                "This usually means the process is running as SYSTEM or the\n"
                "path is protected. Try running as Administrator.",
                parent=self.win,
            )
            return
        try:
            subprocess.Popen(["explorer", f"/select,{path}"])
        except Exception as e:
            messagebox.showerror("Error", f"Could not open Explorer:\n{e}", parent=self.win)

    def _copy_selected_proc_path(self):
        """Copy the selected process's executable path to the system clipboard."""
        path = self._get_selected_proc_path()
        if not path:
            return
        self.win.clipboard_clear()
        self.win.clipboard_append(path)

    def _display_users(self, data):
        """Fill the Users tab with all local accounts and their last-login times."""
        if data.get("error"):
            self.user_summary.config(text=f"  Error: {data['error']}", fg=RED)
            return

        accounts = data.get("accounts", [])
        admins   = [a for a in accounts if a["is_admin"]]

        self.user_summary.config(
            text=f"  {len(accounts)} account(s)  —  {len(admins)} admin(s)",
            fg=YELLOW if len(admins) > 2 else TEXT,
        )

        for acct in accounts:
            admin_str  = "YES" if acct["is_admin"] else "no"
            active_str = "yes" if acct["active"]   else "NO"

            if acct["is_admin"]:
                tag = "admin"
            elif not acct["active"]:
                tag = "inactive"
            else:
                tag = "normal"

            self.user_tree.insert(
                "", "end",
                values=(acct["name"], acct["last_login"], admin_str, active_str),
                tags=(tag,),
            )

        self.user_tree.tag_configure("admin",    foreground=YELLOW)
        self.user_tree.tag_configure("inactive", foreground=TEXT_DIM)
        self.user_tree.tag_configure("normal",   foreground=TEXT)

    def _display_firewall(self, data):
        """Fill the Firewall & Network tab with grouped, colour-coded rows."""
        if data.get("error"):
            self.fw_tree.insert(
                "", "end", values=("ERROR", "Scan failed", data["error"]), tags=("risk",)
            )
            self.fw_tree.tag_configure("risk", foreground=RED)
            return

        def section_header(label):
            self.fw_tree.insert("", "end", values=("", "", ""),    tags=("spacer",))
            self.fw_tree.insert("", "end", values=(label, "", ""), tags=("header",))

        # ── Firewall profiles ─────────────────────────────────────────────────
        section_header("── FIREWALL ──")
        for profile, info in data.get("profiles", {}).items():
            state = info.get("state", "UNKNOWN")
            tag   = "ok" if state == "ON" else "risk"
            self.fw_tree.insert("", "end", values=("Profile", profile, state), tags=(tag,))

        rules = data.get("rules", {})
        self.fw_tree.insert("", "end", values=("Rules", "Inbound",  str(rules.get("inbound",  0))), tags=("neutral",))
        self.fw_tree.insert("", "end", values=("Rules", "Outbound", str(rules.get("outbound", 0))), tags=("neutral",))

        # ── Network adapters ──────────────────────────────────────────────────
        section_header("── ADAPTERS ──")
        for adapter in data.get("adapters", []):
            name = adapter["name"][:35]
            self.fw_tree.insert("", "end", values=("Adapter", name, adapter["ip"]), tags=("neutral",))
            self.fw_tree.insert("", "end", values=("", "MAC",  adapter["mac"]),     tags=("dim",))

        # ── Listening ports ───────────────────────────────────────────────────
        section_header("── LISTENING PORTS ──")
        for lst in data.get("listeners", []):
            is_risky = lst["port"] in self.HIGH_RISK_PORTS
            tag      = "risk" if is_risky else "neutral"
            detail   = f"{lst['proto']}  {lst['process']}{'  (!)' if is_risky else ''}"
            self.fw_tree.insert("", "end", values=("Port", str(lst["port"]), detail), tags=(tag,))

        self.fw_tree.tag_configure("header",  foreground=ACCENT,   font=FONT_LABEL)
        self.fw_tree.tag_configure("ok",      foreground=GREEN)
        self.fw_tree.tag_configure("risk",    foreground=RED)
        self.fw_tree.tag_configure("neutral", foreground=TEXT)
        self.fw_tree.tag_configure("dim",     foreground=TEXT_DIM)
        self.fw_tree.tag_configure("spacer",  foreground=BG)

    # ── AI Analysis ───────────────────────────────────────────────────────────

    def _clear_ai_output(self):
        """Wipe the AI analysis text widget."""
        self.ai_text.config(state="normal")
        self.ai_text.delete("1.0", "end")
        self.ai_text.config(state="disabled")

    def _start_ai_analysis(self):
        """
        Kick off the AI analysis in a background thread.

        Guard: no-op if a scan hasn't been run yet or analysis is already running.
        """
        if self._ai_streaming:
            return
        if not self._last_scan:
            self.ai_status_var.set("No scan data — run a scan first.")
            return

        self._ai_streaming = True
        self.ai_run_btn.config(state="disabled", text="[ ANALYSING... ]")
        self.ai_status_var.set("Analysing scan results...")
        self._clear_ai_output()

        # Switch to the AI tab so the user sees output streaming in
        self.notebook.select(3)

        threading.Thread(
            target=self._run_ai_analysis,
            args=(self._last_scan,),
            daemon=True,
        ).start()

    def _run_ai_analysis(self, scan_results: dict):
        """
        Background worker: drives the analyse() generator and streams each line
        to the text widget via frame.after() for thread safety.
        """
        import time as _time
        nextion_lines = []
        overall_label = "?"

        for line in ai_analyse(scan_results):
            if "Overall rating" in line:
                overall_label = line.split(":")[-1].strip()
            if line.startswith("  •") and len(nextion_lines) < 6:
                nextion_lines.append(line.strip())
            self.frame.after(0, self._append_ai_line, line)
            _time.sleep(0.012)

        self.frame.after(0, self._ai_analysis_done, overall_label, nextion_lines)

    def _append_ai_line(self, line: str):
        """Append one line to the AI text widget with colour tagging. Main thread only."""
        self.ai_text.config(state="normal")

        if line.startswith("═") or line.startswith("──"):
            tag = "header"
        elif "HIGH RISK" in line or "[ HIGH ]" in line or "urgently" in line.lower():
            tag = "high"
        elif "MODERATE" in line or "[ MODERATE ]" in line:
            tag = "moderate"
        elif "LOW RISK" in line or "[ LOW ]" in line:
            tag = "low"
        elif "CLEAN" in line or "[ CLEAN ]" in line or "no concerns" in line.lower():
            tag = "clean"
        else:
            tag = "normal"

        self.ai_text.insert("end", line + "\n", tag)
        self.ai_text.see("end")
        self.ai_text.config(state="disabled")

    def _ai_analysis_done(self, overall_label: str, nextion_lines: list):
        """Reset UI state after analysis completes and push summary to Nextion."""
        self._ai_streaming = False
        self.ai_run_btn.config(state="normal", text="[ RUN ANALYSIS ]")
        self.ai_status_var.set(f"Analysis complete — {overall_label}")
        if self.send_fn:
            self._push_ai_to_nextion(overall_label, nextion_lines)

    def _push_ai_to_nextion(self, overall_label: str, findings: list):
        """
        Push the AI analysis summary to the Nextion display.

        Expected Nextion elements:
            ai_rating.txt  — overall risk label
            ai_rating.pco  — colour matching the risk level
            t_ai_log.txt   — scrolling findings (updated line by line)
        """
        import time as _time
        from config import NX_GREEN, NX_YELLOW, NX_RED
        color = NX_RED if "HIGH" in overall_label else (NX_YELLOW if "MODERATE" in overall_label else NX_GREEN)
        self.send_fn(f'ai_rating.txt="{overall_label}"')
        self.send_fn(f"ai_rating.pco={color}")
        for line in findings:
            truncated = line[:40] if len(line) > 40 else line
            self.send_fn(f't_ai_log.txt="{truncated}"')
            _time.sleep(0.3)

    # ── Nextion integration ───────────────────────────────────────────────────

    def _push_to_nextion(self, results):
        """
        Push a compact three-line scan summary to the Nextion display.

        Expected Nextion elements:
            scan_procs.txt  — unknown process count
            scan_fw.txt     — condensed firewall profile states
            scan_ports.txt  — listening port count + high-risk count
        """
        flagged = len(results["processes"].get("flagged", []))
        self.send_fn(f'scan_procs.txt="{flagged} unknown proc(s)"')

        profiles = results["firewall"].get("profiles", {})
        fw_str   = "  ".join(
            f"{k[:3]}:{v['state']}" for k, v in profiles.items()
        ) or "N/A"
        self.send_fn(f'scan_fw.txt="{fw_str}"')

        listeners   = results["firewall"].get("listeners", [])
        risky_count = sum(1 for lst in listeners if lst["port"] in self.HIGH_RISK_PORTS)
        self.send_fn(f'scan_ports.txt="{len(listeners)} open  {risky_count} risky"')


# ── Standalone entry point ─────────────────────────────────────────────────────

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Security Scanner — Nextion Control Station")
    root.geometry("860x680")
    root.minsize(700, 500)
    root.configure(bg=BG)
    try:
        root.iconbitmap(default="")
    except Exception:
        pass
    SecurityScanWindow(root)
    root.mainloop()