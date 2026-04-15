# ui_widgets.py
# Reusable Tkinter widget factories and the ElementCard component.
# Import into any UI module that needs styled controls.

import tkinter as tk
from tkinter import messagebox

from config import (
    BG, BG2, BG3, BORDER, ACCENT, ACCENT2, GREEN, RED, YELLOW,
    TEXT, TEXT_DIM, TEXT_HEAD,
    FONT_MONO, FONT_MONO_SM, FONT_LABEL, FONT_HEAD,
)


# ── Widget factory functions ──────────────────────────────────────────────────

def styled_btn(parent, text, command, color=ACCENT, width=None):
    """
    Flat button with a hover highlight in the given accent colour.

    On hover: background fills with `color`, text inverts to BG.
    On leave: returns to BG3 background with coloured text.
    """
    kw = dict(
        text=text, command=command,
        bg=BG3, fg=color,
        activebackground=color, activeforeground=BG,
        relief="flat", bd=0, cursor="hand2",
        font=FONT_LABEL, padx=10, pady=5,
        highlightthickness=1,
        highlightbackground=BORDER,
        highlightcolor=color,
    )
    if width:
        kw["width"] = width
    btn = tk.Button(parent, **kw)
    btn.bind("<Enter>", lambda e: btn.config(bg=color,  fg=BG,    highlightbackground=color))
    btn.bind("<Leave>", lambda e: btn.config(bg=BG3,   fg=color, highlightbackground=BORDER))
    return btn


def styled_entry(parent, width=18, textvariable=None):
    """
    Dark-themed text entry with a cyan focus ring.

    Args:
        width:        character width of the field (default 18)
        textvariable: optional tk.StringVar to bind to the entry
    """
    kw = dict(
        bg=BG2, fg=TEXT, insertbackground=ACCENT,
        relief="flat", bd=0, font=FONT_MONO,
        highlightthickness=1,
        highlightbackground=BORDER,
        highlightcolor=ACCENT,
        width=width,
    )
    if textvariable:
        kw["textvariable"] = textvariable
    return tk.Entry(parent, **kw)


def styled_label(parent, text, color=TEXT_DIM, font=FONT_MONO_SM):
    """Dim text label rendered on a BG2 background."""
    return tk.Label(parent, text=text, bg=BG2, fg=color, font=font)


def section_frame(parent, title):
    """
    Bordered section container with a header bar.

    Layout:
        outer (BORDER-coloured 1px frame)
          └─ inner (BG2 background)
               ├─ header row (BG3 + accent title text)
               ├─ 1px separator line
               └─ body frame  ← pack children here

    Returns:
        (outer_frame, body_frame)
        Pack `outer_frame` in the parent; add child widgets to `body_frame`.
    """
    outer = tk.Frame(parent, bg=BORDER, bd=0)
    inner = tk.Frame(outer,  bg=BG2,    bd=0)
    inner.pack(padx=1, pady=1, fill="both", expand=True)

    hdr = tk.Frame(inner, bg=BG3, bd=0)
    hdr.pack(fill="x")
    tk.Label(
        hdr, text=f"  {title}",
        bg=BG3, fg=ACCENT, font=FONT_HEAD, anchor="w", pady=6,
    ).pack(fill="x")

    tk.Frame(inner, bg=BORDER, height=1).pack(fill="x")

    body = tk.Frame(inner, bg=BG2, bd=0)
    body.pack(fill="both", expand=True, padx=8, pady=8)

    return outer, body


# ── ElementCard ───────────────────────────────────────────────────────────────

class ElementCard:
    """
    A single dynamically-added element control row in the ELEMENT CONTROLS panel.

    Each card targets one Nextion element and exposes the appropriate input
    widget for that element's data type:

        .txt        — free-text entry  →  name.txt="value"
        .val        — integer + slider →  name.val=N
        .pco / .bco — named colour dropdown + optional raw numeric override
                                        →  name.pco=NNNNN

    Args:
        parent:    Tkinter parent frame (the scrollable inner canvas frame)
        name:      Nextion element name (e.g. "t3", "g_cpu")
        etype:     element type string — one of ".txt", ".val", ".pco", ".bco"
        send_fn:   callable(cmd: str) that writes a command to the Nextion
        remove_fn: callable(card) that removes this card from the panel
    """

    # Named colour presets (Nextion RGB565 values) shown in the colour dropdown
    COLORS = {
        "Black":  0,
        "White":  65535,
        "Red":    63488,
        "Green":  2016,
        "Blue":   31,
        "Yellow": 65504,
        "Cyan":   2047,
        "Orange": 64512,
        "Grey":   33840,
    }

    # Badge colour per element type for quick visual identification
    _BADGE_COLORS = {
        ".txt": ACCENT,
        ".val": YELLOW,
        ".pco": ACCENT2,
        ".bco": "#b388ff",
    }

    def __init__(self, parent, name: str, etype: str, send_fn, remove_fn):
        self.name      = name
        self.etype     = etype
        self.send_fn   = send_fn
        self.remove_fn = remove_fn

        self.frame = tk.Frame(
            parent, bg=BG3, highlightthickness=1, highlightbackground=BORDER
        )
        self.frame.pack(fill="x", pady=2, padx=2)
        self._build()

    def _build(self):
        """Construct the card's internal layout based on the element type."""
        is_color = self.etype in (".pco", ".bco")
        is_val   = self.etype == ".val"

        # ── Left side: type badge + element name ──────────────────────────────
        left = tk.Frame(self.frame, bg=BG3)
        left.pack(side="left", padx=(8, 4), pady=6)

        badge_color = self._BADGE_COLORS.get(self.etype, TEXT_DIM)

        tk.Label(
            left, text=self.etype, bg=badge_color, fg=BG,
            font=("Consolas", 7, "bold"), padx=4, pady=1,
        ).pack(side="left")

        tk.Label(
            left, text=f"  {self.name}", bg=BG3, fg=TEXT_HEAD, font=FONT_LABEL,
        ).pack(side="left")

        # ── Right side: input controls + SEND + remove (×) ───────────────────
        right = tk.Frame(self.frame, bg=BG3)
        right.pack(side="right", padx=8, pady=4)

        rx = tk.Label(
            right, text="x", bg=BG3, fg=TEXT_DIM,
            font=("Consolas", 10), cursor="hand2", padx=4,
        )
        rx.pack(side="right", padx=(4, 0))
        rx.bind("<Button-1>", lambda e: self.remove_fn(self))
        rx.bind("<Enter>",    lambda e: rx.config(fg=RED))
        rx.bind("<Leave>",    lambda e: rx.config(fg=TEXT_DIM))

        styled_btn(right, "SEND", self._send, color=ACCENT, width=6).pack(
            side="right", padx=(4, 4)
        )

        if is_color:
            self.color_var = tk.StringVar(value="White")
            menu = tk.OptionMenu(right, self.color_var, *list(self.COLORS.keys()))
            menu.config(
                bg=BG2, fg=TEXT, activebackground=ACCENT, activeforeground=BG,
                relief="flat", font=FONT_MONO,
                highlightthickness=1, highlightbackground=BORDER, bd=0,
            )
            menu["menu"].config(
                bg=BG2, fg=TEXT, activebackground=ACCENT, activeforeground=BG,
                font=FONT_MONO,
            )
            menu.pack(side="right", padx=4)
            tk.Label(right, text="or raw:", bg=BG3, fg=TEXT_DIM,
                     font=FONT_MONO_SM).pack(side="right")
            self.entry = styled_entry(right, width=7)
            self.entry.pack(side="right", padx=2)

        elif is_val:
            self.slider_var = tk.IntVar(value=0)
            tk.Scale(
                right, from_=0, to=100, orient="horizontal",
                variable=self.slider_var, length=110,
                bg=BG3, fg=TEXT_DIM, troughcolor=BG,
                activebackground=ACCENT, highlightthickness=0,
                bd=0, font=FONT_MONO_SM, sliderrelief="flat",
            ).pack(side="right", padx=4)
            self.entry = styled_entry(right, width=7)
            self.entry.pack(side="right", padx=2)
            tk.Label(right, text="val:", bg=BG3, fg=TEXT_DIM,
                     font=FONT_MONO_SM).pack(side="right")

        else:
            self.entry = styled_entry(right, width=20)
            self.entry.pack(side="right", padx=4)
            tk.Label(right, text="text:", bg=BG3, fg=TEXT_DIM,
                     font=FONT_MONO_SM).pack(side="right")

    def _send(self):
        """
        Build and dispatch the Nextion command for this element's current value.

        For colour elements: raw numeric override takes priority over the dropdown.
        For val elements:    typed entry takes priority over the slider.
        Validates numeric inputs and shows an error dialog on bad input.
        """
        is_color = self.etype in (".pco", ".bco")
        is_val   = self.etype == ".val"
        raw      = self.entry.get().strip()

        if is_color:
            if raw:
                try:
                    val = int(raw)
                except ValueError:
                    messagebox.showerror("Bad Value", "Raw color must be 0–65535.")
                    return
            else:
                val = self.COLORS.get(self.color_var.get(), 65535)
            cmd = f"{self.name}{self.etype}={val}"

        elif is_val:
            src = raw if raw else str(self.slider_var.get())
            try:
                int(src)
            except ValueError:
                messagebox.showerror("Bad Value", "Value must be an integer.")
                return
            cmd = f"{self.name}{self.etype}={src}"

        else:
            cmd = f'{self.name}{self.etype}="{raw}"'

        self.send_fn(cmd)
