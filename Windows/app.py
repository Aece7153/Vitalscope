# app.py
# NextionControlStation — the main application class.
# Handles UI layout, serial connection, listener thread, and page routing.
# Page-specific refresh logic lives in pages.py (PageHandlersMixin).

import tkinter as tk
from tkinter import ttk, messagebox
import serial
import serial.tools.list_ports
import socket
import psutil
import threading
import time
from collections import deque

from config import (
    DEFAULT_BAUD, DEFAULT_DELAY,
    NX_GREEN, NX_RED, NX_YELLOW,
    PAGE_REFRESH_MAP,
    BG, BG2, BG3, BORDER, ACCENT, ACCENT2, GREEN, RED, YELLOW, TEXT, TEXT_DIM,
    FONT_MONO, FONT_MONO_SM, FONT_LABEL, FONT_HEAD, FONT_TITLE,
)
from ui_widgets import styled_btn, styled_entry, styled_label, section_frame, ElementCard
from pages import PageHandlersMixin
from security_scan import SecurityScanWindow


class NextionControlStation(PageHandlersMixin):
    """
    Root application class for Nextion Control Station.

    Inherits page refresh logic from PageHandlersMixin so that each page's
    Nextion-update code is kept in its own file (pages.py) rather than here.
    """

    def __init__(self, root):
        self.root = root
        self.root.title("NEXTION CONTROL STATION")
        self.root.geometry("960x780")
        self.root.minsize(860, 660)
        self.root.configure(bg=BG)

        # ── Serial ────────────────────────────────────────────────────────────
        self.ser          = None
        self._serial_lock = threading.Lock()  # guards all serial.write() calls

        # ── Application state ─────────────────────────────────────────────────
        self.cpu_history     = deque(maxlen=5)      # rolling average for CPU %
        self.active_page_var = tk.StringVar(value="--")
        self.status_var      = tk.StringVar(value="DISCONNECTED")
        self._current_page   = None                 # name of the active Nextion page
        self.element_cards   = []                   # live ElementCard instances

        # ── Listener thread ───────────────────────────────────────────────────
        self.running_listener = False
        self.listener_thread  = None

        # ── Auto-send (periodic element refresh) ──────────────────────────────
        self._auto_thread = None

        # ── Network quality loop (network page only) ──────────────────────────
        self._net_running    = False
        self._net_thread     = None
        self._net_stop_event = threading.Event()

        # ── Dashboard live update loop ────────────────────────────────────────
        self._dash_running    = False
        self._dash_thread     = None
        self._dash_stop_event = threading.Event()

        self._apply_style()
        self._build_ui()
        self._refresh_ports()

    # ── Tkinter style ─────────────────────────────────────────────────────────

    def _apply_style(self):
        """Configure ttk.Combobox and PanedWindow to match the dark theme."""
        s = ttk.Style()
        s.theme_use("clam")
        s.configure(
            "TCombobox",
            fieldbackground=BG2, background=BG2,
            foreground=TEXT, selectbackground=ACCENT, selectforeground=BG,
            arrowcolor=ACCENT, bordercolor=BORDER,
            lightcolor=BG2, darkcolor=BG2, insertcolor=ACCENT,
        )
        s.configure("TPanedwindow", background=BG)
        s.configure("Sash", sashthickness=5, sashrelief="flat", background=BORDER)

    # ── UI layout ─────────────────────────────────────────────────────────────

    def _build_ui(self):
        """Build the full window layout: title bar, left column, right column."""
        # Title bar
        tb = tk.Frame(self.root, bg=BG3, height=44)
        tb.pack(fill="x")
        tb.pack_propagate(False)
        tk.Label(
            tb, text="  NEXTION CONTROL STATION",
            bg=BG3, fg=ACCENT, font=FONT_TITLE, padx=16,
        ).pack(side="left", pady=8)
        self.status_dot = tk.Label(tb, text="*", bg=BG3, fg=RED, font=("Consolas", 18))
        self.status_dot.pack(side="right", padx=(0, 8))
        tk.Label(
            tb, textvariable=self.status_var, bg=BG3, fg=TEXT_DIM, font=FONT_MONO,
        ).pack(side="right", padx=4)

        # 1-pixel accent separator below the title bar
        tk.Frame(self.root, bg=ACCENT, height=1).pack(fill="x")

        # Main content area — horizontal PanedWindow splits left controls from right panels.
        main = tk.Frame(self.root, bg=BG)
        main.pack(fill="both", expand=True, padx=12, pady=8)

        h_pane = ttk.PanedWindow(main, orient="horizontal")
        h_pane.pack(fill="both", expand=True)

        # Left column — scrollable canvas so all panels stay accessible when narrow
        left_outer = tk.Frame(h_pane, bg=BG)
        h_pane.add(left_outer, weight=0)

        left_canvas = tk.Canvas(left_outer, bg=BG, highlightthickness=0, width=320)
        left_sb = tk.Scrollbar(left_outer, orient="vertical",
                               command=left_canvas.yview, bg=BG3)
        left_canvas.configure(yscrollcommand=left_sb.set)
        left_sb.pack(side="right", fill="y")
        left_canvas.pack(side="left", fill="both", expand=True)

        left = tk.Frame(left_canvas, bg=BG)
        left_win = left_canvas.create_window((0, 0), window=left, anchor="nw")

        left.bind("<Configure>", lambda e: left_canvas.configure(
            scrollregion=left_canvas.bbox("all")))
        left_canvas.bind("<Configure>", lambda e: left_canvas.itemconfig(
            left_win, width=e.width))
        left_canvas.bind("<MouseWheel>", lambda e: left_canvas.yview_scroll(
            int(-1 * (e.delta / 120)), "units"))

        # Right column — vertical split: element controls (top) | log (bottom)
        right_outer = tk.Frame(h_pane, bg=BG)
        h_pane.add(right_outer, weight=1)

        v_pane = ttk.PanedWindow(right_outer, orient="vertical")
        v_pane.pack(fill="both", expand=True)

        elem_frame = tk.Frame(v_pane, bg=BG)
        v_pane.add(elem_frame, weight=1)

        log_frame = tk.Frame(v_pane, bg=BG)
        v_pane.add(log_frame, weight=2)

        self._build_connection_panel(left)
        self._build_autosend_panel(left)
        self._build_setup_panel(left)
        self._build_custom_cmd_panel(left)
        self._build_scan_launcher(left)
        self._build_threat_simulator(left)

        self._build_elements_panel(elem_frame)
        self._build_log_panel(log_frame)

    def _build_connection_panel(self, parent):
        """Serial port + baud selection and the Connect/Disconnect button."""
        outer, body = section_frame(parent, "CONNECTION")
        outer.pack(fill="x", pady=(0, 6))

        row1 = tk.Frame(body, bg=BG2)
        row1.pack(fill="x", pady=2)
        styled_label(row1, "PORT").pack(side="left", padx=(0, 6))
        self.port_combo = ttk.Combobox(row1, width=9, font=FONT_MONO, state="normal")
        self.port_combo.pack(side="left")
        self.port_manual = styled_entry(row1, width=8)
        self.port_manual.insert(0, "COM8")
        self.port_manual.pack(side="left", padx=(4, 0))
        styled_label(row1, " manual").pack(side="left", padx=2)
        styled_btn(row1, "R", self._refresh_ports, color=TEXT_DIM, width=2).pack(side="right")

        row2 = tk.Frame(body, bg=BG2)
        row2.pack(fill="x", pady=2)
        styled_label(row2, "BAUD").pack(side="left", padx=(0, 6))
        self.baud_combo = ttk.Combobox(
            row2,
            values=["9600", "19200", "38400", "57600", "115200"],
            width=9, font=FONT_MONO,
        )
        self.baud_combo.set(str(DEFAULT_BAUD))
        self.baud_combo.pack(side="left")

        row3 = tk.Frame(body, bg=BG2)
        row3.pack(fill="x", pady=(6, 2))
        self.connect_btn = styled_btn(
            row3, "[ CONNECT ]", self.toggle_connection, color=GREEN, width=22
        )
        self.connect_btn.pack(fill="x")

    def _build_autosend_panel(self, parent):
        """Checkbox + interval spinbox for periodic element re-sends."""
        outer, body = section_frame(parent, "AUTO-SEND")
        outer.pack(fill="x", pady=(0, 6))

        row = tk.Frame(body, bg=BG2)
        row.pack(fill="x")

        self.auto_var      = tk.BooleanVar(value=False)
        self.auto_interval = tk.IntVar(value=5)

        tk.Checkbutton(
            row, text="Auto-send all every", variable=self.auto_var,
            bg=BG2, fg=TEXT_DIM, activebackground=BG2, selectcolor=BG3,
            font=FONT_MONO_SM, command=self._toggle_auto,
        ).pack(side="left")

        tk.Spinbox(
            row, from_=1, to=60, width=3, textvariable=self.auto_interval,
            bg=BG3, fg=ACCENT, insertbackground=ACCENT,
            buttonbackground=BG3, relief="flat", font=FONT_MONO_SM,
        ).pack(side="left", padx=2)

        tk.Label(row, text="s", bg=BG2, fg=TEXT_DIM, font=FONT_MONO_SM).pack(side="left")

    def _build_setup_panel(self, parent):
        """Run Setup Sequence button — navigates to a page and sweeps gauges."""
        outer, body = section_frame(parent, "SETUP SEQUENCE")
        outer.pack(fill="x", pady=(0, 6))

        row = tk.Frame(body, bg=BG2)
        row.pack(fill="x")
        styled_label(row, "PAGE:").pack(side="left", padx=(0, 4))
        self.setup_page_entry = styled_entry(row, width=10)
        self.setup_page_entry.insert(0, "home")
        self.setup_page_entry.pack(side="left")

        styled_btn(
            body, "[ RUN SETUP ANIMATION ]",
            self.run_setup_sequence, color=ACCENT2,
        ).pack(fill="x", pady=(6, 0))

    def _build_custom_cmd_panel(self, parent):
        """Free-text entry for sending arbitrary Nextion commands."""
        outer, body = section_frame(parent, "CUSTOM COMMAND")
        outer.pack(fill="x", pady=(0, 6))

        self.custom_entry = styled_entry(body, width=30)
        self.custom_entry.pack(fill="x", pady=(0, 4))
        self.custom_entry.bind("<Return>", lambda e: self._send_custom())

        styled_btn(body, "SEND [Enter]", self._send_custom, color=ACCENT).pack(fill="x")

    def _build_elements_panel(self, parent):
        """ELEMENT CONTROLS panel — add/remove ElementCard rows for Nextion elements."""
        outer, body = section_frame(parent, "ELEMENT CONTROLS")
        outer.pack(fill="both", expand=False, pady=(0, 6))

        add_row = tk.Frame(body, bg=BG2)
        add_row.pack(fill="x", pady=(0, 6))

        styled_label(add_row, "NAME:").pack(side="left", padx=(0, 4))
        self.elem_name_entry = styled_entry(add_row, width=14)
        self.elem_name_entry.pack(side="left", padx=(0, 8))
        self.elem_name_entry.bind("<Return>", lambda e: self._add_element())

        styled_label(add_row, "TYPE:").pack(side="left", padx=(0, 4))
        self.elem_type_var = tk.StringVar(value=".txt")

        menu = tk.OptionMenu(add_row, self.elem_type_var, ".txt", ".val", ".pco", ".bco")
        menu.config(
            bg=BG2, fg=TEXT, activebackground=ACCENT, activeforeground=BG,
            relief="flat", font=FONT_MONO,
            highlightthickness=1, highlightbackground=BORDER, bd=0, width=4,
        )
        menu["menu"].config(
            bg=BG2, fg=TEXT, activebackground=ACCENT, activeforeground=BG, font=FONT_MONO,
        )
        menu.pack(side="left", padx=(0, 8))

        styled_btn(add_row, "+ ADD",     self._add_element,    color=GREEN).pack(side="left")
        styled_btn(add_row, "CLEAR ALL", self._clear_elements, color=RED).pack(side="right")

        tk.Frame(body, bg=BORDER, height=1).pack(fill="x", pady=(0, 4))

        canvas_frame = tk.Frame(body, bg=BG2)
        canvas_frame.pack(fill="both", expand=True)

        self.elem_canvas = tk.Canvas(canvas_frame, bg=BG2, highlightthickness=0, height=180)
        sb = tk.Scrollbar(canvas_frame, orient="vertical", command=self.elem_canvas.yview, bg=BG3)
        self.elem_canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.elem_canvas.pack(side="left", fill="both", expand=True)

        self.elem_inner = tk.Frame(self.elem_canvas, bg=BG2)
        self._elem_win  = self.elem_canvas.create_window(
            (0, 0), window=self.elem_inner, anchor="nw"
        )

        self.elem_inner.bind(
            "<Configure>",
            lambda e: self.elem_canvas.configure(scrollregion=self.elem_canvas.bbox("all")),
        )
        self.elem_canvas.bind(
            "<Configure>",
            lambda e: self.elem_canvas.itemconfig(self._elem_win, width=e.width),
        )
        self.elem_canvas.bind(
            "<MouseWheel>",
            lambda e: self.elem_canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"),
        )

    def _build_log_panel(self, parent):
        """
        SERIAL LOG panel — append-only coloured log of all sent/received data.

        Log tags and their colours:
            send  — cyan    (commands sent to the Nextion)
            recv  — green   (raw lines received from Pico)
            ok    — green   (success events)
            error — red     (errors and failures)
            info  — yellow  (general informational messages)
            dim   — grey    (verbose / background thread messages)
            page  — orange  (page-change events)
            net   — purple  (network quality updates)
        """
        outer, body = section_frame(parent, "SERIAL LOG")
        outer.pack(fill="both", expand=True)

        ctrl = tk.Frame(body, bg=BG2)
        ctrl.pack(fill="x", pady=(0, 4))

        styled_btn(ctrl, "CLEAR", self.clear_log, color=TEXT_DIM, width=8).pack(side="right")

        self.autoscroll_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            ctrl, text="Auto-scroll", variable=self.autoscroll_var,
            bg=BG2, fg=TEXT_DIM, activebackground=BG2, selectcolor=BG3,
            font=FONT_MONO_SM,
        ).pack(side="right", padx=8)

        tk.Label(ctrl, text="PAGE:", bg=BG2, fg=TEXT_DIM, font=FONT_MONO_SM).pack(side="left")
        tk.Label(ctrl, textvariable=self.active_page_var,
                 bg=BG2, fg=ACCENT2, font=FONT_LABEL).pack(side="left", padx=(4, 2))

        self.log_box = tk.Text(
            body, bg=BG, fg=TEXT, insertbackground=ACCENT,
            relief="flat", bd=0, font=FONT_MONO, state="disabled",
            wrap="word", highlightthickness=1, highlightbackground=BORDER,
        )
        sb = tk.Scrollbar(body, command=self.log_box.yview, bg=BG3)
        self.log_box.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.log_box.pack(fill="both", expand=True)

        for tag, color in [
            ("send",  ACCENT),
            ("recv",  "#39ff14"),
            ("ok",    "#39ff14"),
            ("error", RED),
            ("info",  YELLOW),
            ("dim",   TEXT_DIM),
            ("page",  ACCENT2),
            ("net",   "#b388ff"),
        ]:
            self.log_box.tag_config(tag, foreground=color)

    # ── Port management ───────────────────────────────────────────────────────

    def _refresh_ports(self):
        """Repopulate the port dropdown with currently available COM ports."""
        ports = [p.device for p in serial.tools.list_ports.comports()]
        self.port_combo["values"] = ports
        if ports:
            self.port_combo.set(ports[0])

    def _get_port(self):
        """
        Return the port to connect to.

        Prefers the manual-entry field if it contains text; falls back to the
        dropdown selection.
        """
        manual = self.port_manual.get().strip()
        return manual if manual else self.port_combo.get().strip()

    # ── Connection lifecycle ──────────────────────────────────────────────────

    def toggle_connection(self):
        """Connect if disconnected, or disconnect if already connected."""
        if self.ser:
            self.disconnect()
        else:
            self.connect()

    def connect(self):
        """Open the serial port and start the listener thread."""
        port = self._get_port()
        try:
            baud = int(self.baud_combo.get())
        except ValueError:
            baud = DEFAULT_BAUD

        try:
            self.ser = serial.Serial(port, baud, timeout=1, write_timeout=2)
            self.log(f"Connected to {port} @ {baud}", "ok")
            self.status_var.set(f"CONNECTED  {port}")
            self.status_dot.config(fg="#39ff14")
            self.connect_btn.config(text="[ DISCONNECT ]")
            self.start_listener()
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not open {port}:\n{e}")

    def _post_connect_sequence(self):
        """
        Fired when the Pico sends "page_main" on boot — signals it is ready.

        Runs in a daemon thread to avoid blocking the main thread during handshake.
        """
        threading.Thread(target=self._do_connect_cmds, daemon=True).start()

    def _do_connect_cmds(self):
        """Send the initial PC-connected status commands to the Nextion."""
        self._send_raw_cmd('pc_status.txt="Connected"')
        self._send_raw_cmd(f"pc_status.pco={NX_GREEN}")
        self._send_raw_cmd("pc_con.val=1")
        self._queue_log("Nextion pc_status set to Connected (green)", "ok")

    def disconnect(self):
        """
        Stop all background loops, signal disconnection to the Nextion, and close serial.

        Order: stop loops first so they cannot race on the serial port while
        we're writing the disconnect commands. Then signal the listener before
        sleeping so it notices immediately rather than after a blind delay.
        """
        self._stop_net_loop()
        self._stop_dash_loop()

        # Send disconnect status to the display (best-effort; port may be gone)
        if self.ser:
            try:
                for cmd in [
                    'pc_status.txt="Disconnected"',
                    f'pc_status.pco={NX_RED}',
                    'pc_con.val=0',
                ]:
                    self.ser.write(cmd.encode("ascii") + b'\n')
                    self.ser.flush()
                    time.sleep(0.08)
            except Exception:
                pass

        # Signal the listener thread to stop, then give it time to exit cleanly
        self.running_listener = False
        time.sleep(0.15)

        if self.ser:
            try:
                self.ser.close()
            except Exception:
                pass

        # Reset all state
        self.ser             = None
        self._current_page   = None
        self._net_stop_event.set()
        self._dash_stop_event.set()
        self.active_page_var.set("--")
        self.status_var.set("DISCONNECTED")
        self.status_dot.config(fg=RED)
        self.connect_btn.config(text="[ CONNECT ]")
        self.log("Serial closed.", "info")

    # ── Serial listener ───────────────────────────────────────────────────────

    def start_listener(self):
        """
        Start a background thread that reads lines from the Pico over USB serial.

        Accumulates bytes into a buffer and dispatches complete newline-terminated
        lines to _handle_incoming() on the main thread via root.after().

        Page-change detection also stops the relevant background loops immediately
        on the listener thread to prevent stale writes from the previous page.
        """
        self.running_listener = True
        buffer = bytearray()

        def _run():
            nonlocal buffer
            while self.running_listener:
                try:
                    if self.ser and self.ser.in_waiting:
                        buffer.extend(self.ser.read(self.ser.in_waiting))

                        while b'\n' in buffer:
                            idx  = buffer.index(b'\n')
                            line = buffer[:idx].decode(errors='ignore').strip()
                            buffer = buffer[idx + 1:]

                            if not line:
                                continue

                            # Detect page changes on this thread so loops for the
                            # old page stop before the new page's commands arrive.
                            if "[PC_CMD]" not in line:
                                stripped = line
                                for prefix in ("[NEX_MSG]", "[RECV]", "[PICO]"):
                                    stripped = stripped.replace(prefix, "").strip()

                                if stripped.startswith("page_"):
                                    pg = stripped[len("page_"):].strip().lower()
                                    if pg != "network":
                                        self._stop_net_loop()
                                    if pg not in ("dashboard", "main"):
                                        self._stop_dash_loop()

                            self.root.after(0, self._handle_incoming, line)
                    else:
                        time.sleep(0.01)

                except Exception as e:
                    self.root.after(0, self.log, f"Listener error: {e}", "error")
                    time.sleep(0.2)

        self.listener_thread = threading.Thread(target=_run, daemon=True)
        self.listener_thread.start()

    def _handle_incoming(self, line: str):
        """
        Dispatch a line received from the Pico. Must run on the main thread.

        Recognised message types:
            page_<n>     — Nextion switched to a named page
            [PC_CMD] ... — echo of a command we sent (logged, otherwise ignored)
        """
        tag = "recv"
        if "[ERROR]" in line:
            tag = "error"
        elif "[OK]" in line or "[PICO]" in line:
            tag = "ok"
        self.log(line, tag)

        if "[PC_CMD]" in line:
            return

        stripped = line
        for prefix in ("[NEX_MSG]", "[RECV]", "[PICO]"):
            stripped = stripped.replace(prefix, "").strip()

        if stripped.startswith("page_"):
            page_name = stripped[len("page_"):].strip().lower()
            self._on_page_change(page_name)

    def _on_page_change(self, page_name: str):
        """
        Handle a Nextion page-change event.

        Stops loops belonging to the previous page, updates current page state,
        and fires the auto-refresh functions mapped to the new page.
        """
        if page_name != "network":
            self._stop_net_loop()
        if page_name not in ("dashboard", "main"):
            self._stop_dash_loop()

        prev_page          = self._current_page
        self._current_page = page_name
        self.active_page_var.set(page_name)

        # First "page_main" after connection = Pico has finished booting
        if page_name == "main" and prev_page is None:
            self._post_connect_sequence()

        funcs = PAGE_REFRESH_MAP.get(page_name)
        if not funcs:
            self.log(f"   (no data refresh for '{page_name}')", "dim")
            return

        threading.Thread(
            target=self._run_page_refresh, args=(funcs,), daemon=True
        ).start()

    def _run_page_refresh(self, funcs: list):
        """
        Call each refresh function in `funcs` after a short settle delay.

        The 0.5 s delay ensures the page has fully loaded on the Nextion
        before refresh commands are sent.
        """
        time.sleep(0.5)
        for fn_name in funcs:
            fn = getattr(self, fn_name, None)
            if callable(fn):
                fn()

    # ── Dashboard live update loop ────────────────────────────────────────────

    def _stop_dash_loop(self):
        """Signal the dashboard loop to stop. Returns immediately (non-blocking)."""
        self._dash_stop_event.set()
        self._dash_running = False

    def _start_dash_loop(self):
        """Start the dashboard live update loop (3-second CPU/RAM/Disk refresh)."""
        if self._current_page not in ("dashboard", "main") or self._dash_running:
            return
        self._dash_stop_event.clear()
        self._dash_running = True
        self._dash_thread  = threading.Thread(target=self._dash_loop, daemon=True)
        self._dash_thread.start()
        self._queue_log("  [dashboard] live update loop started", "dim")

    def _dash_loop(self):
        """Update CPU, RAM, and Disk every 3 seconds while on the dashboard/main page."""
        self._queue_log("  [dashboard] live loop running", "dim")
        while not self._dash_stop_event.is_set():
            self._dash_stop_event.wait(timeout=3.0)
            if self._dash_stop_event.is_set():
                break
            self.send_cpu()
            self.send_ram()
            self.send_disk()
        self._dash_running = False
        self._queue_log("  [dashboard] live loop stopped", "dim")

    # ── Serial send helpers ───────────────────────────────────────────────────

    def _send_raw_cmd(self, cmd: str) -> bool:
        """
        Write one command to serial (thread-safe, no Tkinter calls).

        Uses a newline terminator — the Pico's USB CDC reader uses readline().
        Acquires the serial lock so concurrent threads do not interleave writes.

        Returns:
            True if the write succeeded, False if not connected or on error.
        """
        if not self.ser:
            return False
        with self._serial_lock:
            try:
                self.ser.write(cmd.encode("ascii") + b'\n')
                self.ser.flush()
                time.sleep(DEFAULT_DELAY)
                return True
            except Exception as e:
                self.root.after(0, self.log, f"Send error: {e}", "error")
                return False

    def send(self, cmd: str):
        """
        Public send — safe to call from any thread.

        Logs the outgoing command to the serial log before sending.
        """
        if not self.ser:
            self.root.after(0, self.log, "Not connected.", "error")
            return
        self.root.after(0, self.log, f"-> {cmd}", "send")
        self._send_raw_cmd(cmd)

    def _queue_log(self, msg: str, tag: str = "dim"):
        """Thread-safe log helper — schedules log() on the main thread via root.after."""
        self.root.after(0, self.log, msg, tag)

    def _send_custom(self):
        """Send the contents of the custom command entry field."""
        cmd = self.custom_entry.get().strip()
        if cmd:
            self.send(cmd)

    # ── Element card management ───────────────────────────────────────────────

    def _add_element(self):
        """
        Create a new ElementCard from the name entry and type dropdown.

        Validates that a name was entered and that the (name, type) pair is not
        already present in the panel.
        """
        name  = self.elem_name_entry.get().strip()
        etype = self.elem_type_var.get()

        if not name:
            messagebox.showwarning("Missing Name", "Enter an element name.")
            return

        for c in self.element_cards:
            if c.name == name and c.etype == etype:
                messagebox.showwarning("Duplicate", f"{name}{etype} already exists.")
                return

        card = ElementCard(self.elem_inner, name, etype, self.send, self._remove_element)
        self.element_cards.append(card)
        self.elem_name_entry.delete(0, "end")

    def _remove_element(self, card):
        """Destroy an ElementCard widget and remove it from the tracking list."""
        card.frame.destroy()
        self.element_cards.remove(card)

    def _clear_elements(self):
        """Remove all element cards after user confirmation."""
        if self.element_cards and messagebox.askyesno(
            "Clear All", "Remove all element controls?"
        ):
            for c in list(self.element_cards):
                c.frame.destroy()
            self.element_cards.clear()

    # ── System metrics ────────────────────────────────────────────────────────

    def get_ip(self):
        """Return the machine's local IP address, or '0.0.0.0' on failure."""
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "0.0.0.0"

    def get_cpu(self):
        """
        Return a smoothed CPU usage percentage (rolling average of last 5 samples).

        Uses a 0.2-second blocking interval for psutil's measurement window.
        """
        self.cpu_history.append(psutil.cpu_percent(interval=0.2))
        return round(sum(self.cpu_history) / len(self.cpu_history), 1)

    def get_ram(self):
        """Return current RAM usage as a percentage."""
        return psutil.virtual_memory().percent

    def get_disk(self):
        """Return disk usage percentage for the root volume."""
        return psutil.disk_usage("/").percent

    def get_name(self):
        """Return this machine's hostname."""
        return socket.gethostname()

    @staticmethod
    def _gauge_color(value: int) -> int:
        """
        Return the Nextion RGB565 colour appropriate for a usage percentage gauge.

            < 33%  → green  (low usage, healthy)
            < 66%  → yellow (moderate, worth watching)
            ≥ 66%  → red    (high usage, action may be needed)
        """
        if value < 33:
            return NX_GREEN
        if value < 66:
            return NX_YELLOW
        return NX_RED

    def send_ip(self):      self.send(f't_ip.txt="{self.get_ip()}"')
    def send_pc_name(self): self.send(f't_pcname.txt="{self.get_name()}"')

    def send_cpu(self):
        """Push CPU percentage, gauge value, and gauge colour to the Nextion."""
        cpu = int(round(self.get_cpu()))
        self.send(f'p_cpu.txt="{cpu}%"')
        self.send(f'g_cpu.val={cpu}')
        self.send(f'g_cpu.pco={self._gauge_color(cpu)}')

    def send_ram(self):
        """Push RAM percentage, gauge value, and gauge colour to the Nextion."""
        ram = int(round(self.get_ram()))
        self.send(f'p_ram.txt="{ram}%"')
        self.send(f'g_ram.val={ram}')
        self.send(f'g_ram.pco={self._gauge_color(ram)}')

    def send_disk(self):
        """Push disk percentage, gauge value, and gauge colour to the Nextion."""
        disk = int(round(self.get_disk()))
        self.send(f'p_disk.txt="{disk}%"')
        self.send(f'g_disk.val={disk}')
        self.send(f'g_disk.pco={self._gauge_color(disk)}')

    def send_all_sys(self):
        """Push IP, CPU, RAM, and disk in one call (used by auto-send loop)."""
        self.send_ip()
        self.send_cpu()
        self.send_ram()
        self.send_disk()

    # ── Auto-send ─────────────────────────────────────────────────────────────

    AUTO_SEND_MAP = {
        "main":      "send_all_sys",
        "dashboard": "send_all_sys",
    }

    def _toggle_auto(self):
        """Start the auto-send loop when the checkbox is ticked."""
        if self.auto_var.get():
            self._auto_thread = threading.Thread(target=self._auto_loop, daemon=True)
            self._auto_thread.start()

    def _auto_loop(self):
        """
        Periodically call the page's send function while auto-send is enabled.

        Sleeps in 0.1-second increments so the loop exits promptly when the
        checkbox is cleared.
        """
        while self.auto_var.get():
            fn_name = self.AUTO_SEND_MAP.get(self._current_page)
            if fn_name:
                fn = getattr(self, fn_name, None)
                if callable(fn):
                    self.root.after(0, fn)

            for _ in range(self.auto_interval.get() * 10):
                if not self.auto_var.get():
                    return
                time.sleep(0.1)

    # ── Security scan ─────────────────────────────────────────────────────────

    def _build_scan_launcher(self, parent):
        """Security scan launch button at the bottom of the left panel."""
        outer, body = section_frame(parent, "SECURITY SCAN")
        outer.pack(fill="x", pady=(0, 6))
        styled_btn(
            body, "[ RUN SECURITY SCAN ]",
            self.open_security_scan, color=RED,
        ).pack(fill="x")

    def _build_threat_simulator(self, parent):
        """
        THREAT SIMULATOR panel — injects fake threat data to the Nextion display
        so you can see how each page looks when things go wrong.

        Two scenarios:
            Malware  — fake high-risk processes and suspicious open ports
            DDoS     — CPU/RAM/disk spike with network quality collapse
        """
        outer, body = section_frame(parent, "THREAT SIMULATOR")
        outer.pack(fill="x", pady=(0, 6))

        tk.Label(
            body, text="Pushes fake threat data to the display.",
            bg=BG2, fg=TEXT_DIM, font=FONT_MONO_SM, anchor="w",
        ).pack(fill="x", pady=(0, 6))

        btn_row = tk.Frame(body, bg=BG2)
        btn_row.pack(fill="x", pady=(0, 4))

        styled_btn(
            btn_row, "MALWARE SIM",
            self._sim_malware, color=RED, width=12,
        ).pack(side="left", padx=(0, 4))

        styled_btn(
            btn_row, "DDoS SIM",
            self._sim_ddos, color=YELLOW, width=12,
        ).pack(side="left")

        styled_btn(
            body, "[ CLEAR SIM ]",
            self._sim_clear, color=TEXT_DIM,
        ).pack(fill="x", pady=(4, 0))

    # ── Threat simulation ─────────────────────────────────────────────────────

    def _sim_malware(self):
        """
        Simulate a malware infection scenario on page_procs.

        Navigates to page_procs then pushes four fake high-risk processes
        into the name, score, and flag elements.
        """
        if not self.ser:
            self.log("Sim: not connected.", "error")
            return
        self.log("[ SIM ] Malware scenario starting...", "info")
        threading.Thread(target=self._run_sim_malware, daemon=True).start()

    def _run_sim_malware(self):
        # Navigate to the procs page so the data is visible
        self._send_raw_cmd("page page_procs")
        time.sleep(0.6)

        fake_procs = [
            (
                "svch0st.exe",
                "92/100",
                "name looks like hex string; running from temp dir",
            ),
            (
                "xvzqtbmf.exe",
                "85/100",
                "very high name entropy — looks randomly generated",
            ),
            (
                "winlogon32.exe",
                "71/100",
                "not running from a standard system directory",
            ),
            (
                "a3f9b2c1.exe",
                "63/100",
                "path could not be resolved — process may be hidden",
            ),
        ]
        name_els  = ["t2",  "t9",  "t15", "t13"]
        score_els = ["t6",  "t10", "t16", "t12"]
        flag_els  = ["t7",  "t8",  "t14", "t11"]

        for i, (name, score, flag) in enumerate(fake_procs):
            self._send_raw_cmd(f'{name_els[i]}.txt="{name}"')
            self._send_raw_cmd(f'{score_els[i]}.txt="{score}"')
            self._send_raw_cmd(f'{flag_els[i]}.txt="{flag}"')

        self._queue_log("[ SIM ] Malware: procs page injected", "ok")

    def _sim_ddos(self):
        """
        Simulate a DDoS attack scenario on page_network.

        Navigates to page_network then collapses quality score, latency,
        packet loss, speeds, and internet status.
        """
        if not self.ser:
            self.log("Sim: not connected.", "error")
            return
        self.log("[ SIM ] DDoS scenario starting...", "info")
        threading.Thread(target=self._run_sim_ddos, daemon=True).start()

    def _run_sim_ddos(self):
        from config import QUALITY_GAUGE

        # Navigate to the network page so the data is visible
        self._send_raw_cmd("page page_network")
        time.sleep(0.6)

        self._send_raw_cmd(f'{QUALITY_GAUGE}.val=4')
        self._send_raw_cmd(f'{QUALITY_GAUGE}.pco={NX_RED}')
        self._send_raw_cmd('t5.txt="4"')
        self._send_raw_cmd('t3.txt="850ms"')
        self._send_raw_cmd('t7.txt="75%"')
        self._send_raw_cmd('int_status.txt="Degraded"')
        self._send_raw_cmd(f'int_status.pco={NX_RED}')
        self._send_raw_cmd('dwnld_status.txt="0.1 Mbps"')
        self._send_raw_cmd('upld_status.txt="0.0 Mbps"')

        self._queue_log("[ SIM ] DDoS: network page injected", "ok")

    def _sim_clear(self):
        """
        Clear all simulated data by re-running the real refresh for the
        current page, restoring live values.
        """
        if not self.ser:
            self.log("Sim: not connected.", "error")
            return
        self.log("[ SIM ] Clearing — refreshing current page with live data...", "info")
        if self._current_page:
            self._on_page_change(self._current_page)
        else:
            self.log("[ SIM ] No active page to refresh.", "info")

    def open_security_scan(self):
        """Open the security scan Toplevel window."""
        SecurityScanWindow(self.root)

    # ── Setup sequence ────────────────────────────────────────────────────────

    def run_setup_sequence(self):
        """
        Navigate to a target page, set pc_status, and sweep gauges 0→100→0.

        Runs in a background thread so the UI stays responsive during the animation.
        Guard: no-op if serial is not connected.
        """
        if not self.ser:
            self.log("Not connected — cannot run setup.", "error")
            return

        page = self.setup_page_entry.get().strip() or "home"

        def _run():
            self.send(f"page {page}")
            time.sleep(0.3)
            self.send('pc_status.txt="Connected"')
            self.send(f"pc_status.pco={NX_GREEN}")
            self.send("pc_con.val=1")

            # Sweep 0 → 100 → 0 in steps of 20, avoiding the duplicate 100 step
            sweep = list(range(0, 101, 20)) + list(range(80, -1, -20))
            for i in sweep:
                self.send(f"g_cpu.val={i}")
                self.send(f"g_ram.val={i}")
                self.send(f"g_disk.val={i}")
                time.sleep(0.08)

            self.send_all_sys()
            self._queue_log("Setup sequence complete.", "ok")

        threading.Thread(target=_run, daemon=True).start()

    # ── Log ───────────────────────────────────────────────────────────────────

    def log(self, msg: str, tag: str = "dim"):
        """
        Append a timestamped, colour-tagged line to the serial log.

        Must be called on the main thread. Use _queue_log() from background threads.
        """
        ts = time.strftime("%H:%M:%S")
        self.log_box.config(state="normal")
        self.log_box.insert("end", f"{ts}  ", "dim")
        self.log_box.insert("end", msg + "\n", tag)
        if self.autoscroll_var.get():
            self.log_box.see("end")
        self.log_box.config(state="disabled")

    def clear_log(self):
        """Wipe all content from the serial log widget."""
        self.log_box.config(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.config(state="disabled")