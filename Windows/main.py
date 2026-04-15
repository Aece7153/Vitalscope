# main.py
# Entry point for Nextion Control Station.
#
# Usage:

#   python main.py
#
# Dependencies:
#   pip install pyserial psutil

import tkinter as tk
from app import NextionControlStation

if __name__ == "__main__":
    root = tk.Tk()

    # Suppress the default Tk icon on platforms that support it.
    try:
        root.iconbitmap(default="")
    except Exception:
        pass

    app = NextionControlStation(root)
    root.mainloop()
