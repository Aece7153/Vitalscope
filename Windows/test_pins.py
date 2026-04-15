#!/usr/bin/env python3
"""
test_pins.py — Interactive Nextion command sender (PC side, soft UART via TTL adapter).

Sends typed commands to a Nextion display through a USB-to-TTL serial adapter.
Each command is terminated with the 3-byte Nextion terminator (0xFF 0xFF 0xFF).

Usage:
    python test_pins.py
    > t_net.txt="192.168.0.50"
    > exit
"""

import serial
import time

# ── Configuration ─────────────────────────────────────────────────────────────
PC_PORT    = "COM3"               # Change to your adapter's port (e.g. /dev/ttyUSB0 on Linux)
BAUD       = 4800
TERMINATOR = b'\xff\xff\xff'      # Nextion 3-byte command terminator
# ──────────────────────────────────────────────────────────────────────────────


def main():
    with serial.Serial(PC_PORT, BAUD, timeout=0.1) as ser:
        time.sleep(1)  # give the serial adapter time to settle after opening

        print("Type Nextion commands to send (e.g., t_net.txt=\"192.168.0.50\")")
        print("Type 'exit' or 'quit' to close.\n")

        while True:
            try:
                cmd = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if cmd.lower() in ("exit", "quit"):
                break
            if not cmd:
                continue

            ser.write(cmd.encode("utf-8") + TERMINATOR)
            print(f"Sent: {cmd}")


if __name__ == "__main__":
    main()
