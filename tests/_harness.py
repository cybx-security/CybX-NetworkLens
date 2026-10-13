"""Shared bits for the GUI smoke tests: a pump that always returns, stubbed dialogs."""
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
os.environ["CYBX_NO_ELEVATE"] = "1"


def scratch(name: str) -> Path:
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(tempfile.mkdtemp(prefix="networklens-"))
    out = base / name
    out.mkdir(parents=True, exist_ok=True)
    return out


def make_pump(root):
    def pump(cond=lambda: True, timeout=0.2):
        end = time.time() + timeout
        while True:
            root.after(50, root.quit)
            root.mainloop()
            if cond():
                return True
            if time.time() >= end:
                return False
    return pump


def stub_dialogs(answer_yes=True):
    from tkinter import messagebox
    seen = []
    messagebox.askyesno = lambda title, msg="", **k: (seen.append((title, msg)) or answer_yes)
    messagebox.showinfo = lambda title, msg="", **k: seen.append((title, msg))
    messagebox.showwarning = lambda title, msg="", **k: seen.append((title, msg))
    messagebox.showerror = lambda title, msg="", **k: seen.append((title, msg))
    return seen
