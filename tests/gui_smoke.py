"""Real nmap: a quick scan to completion, a stopped scan, and quitting mid-scan."""
import shutil
from _harness import scratch, make_pump, stub_dialogs
import tkinter as tk
import gui

out = scratch("gui_smoke"); shutil.rmtree(out, ignore_errors=True); out.mkdir()
seen = stub_dialogs()
root = tk.Tk(); app = gui.ScannerGUI(root); app.output_dir = out
app.config.setdefault("output", {})["insights_events"] = {"enabled": True, "path": str(out / "feed.ndjson")}
pump = make_pump(root)
logtext = lambda: app.log.get("1.0", "end")
assert "Reports are saved to" in logtext() and "Insights feed" in logtext()

app.target_var.set("127.0.0.1"); app.ports_var.set("22,80,443,5000,7000")
app.mode_var.set("quick"); app._apply_mode()
app.start_scan()
assert pump(lambda: not app._scan_running() and app.event_queue.empty() and app.last_output is not None, 120), logtext()[-600:]
print("scan1 status:", app.status_var.get())
files = sorted(p.name for p in out.iterdir()); print("files:", files)
assert any(f.endswith(".json") for f in files) and any(f.endswith(".html") for f in files) and "feed.ndjson" in files
assert str(app.start_btn["state"]) == "normal" and str(app.stop_btn["state"]) == "disabled"
assert len(app.inv_tree.get_children()) == 1

app.ports_var.set("1-65535"); app.max_rate_var.set("20")
app.start_scan()
assert pump(lambda: app.proc is not None and app.proc.poll() is None and "$ " in logtext(), 20)
pump(timeout=1.0)
app.stop_scan()
assert pump(lambda: not app._scan_running() and app.event_queue.empty(), 30)
print("scan2 status:", app.status_var.get())
assert "stopped" in app.status_var.get().lower(), app.status_var.get()
assert "Failed to parse" not in logtext()

app.start_scan()
assert pump(lambda: app.proc is not None and app.proc.poll() is None, 20)
proc = app.proc
app.on_close()
assert proc.poll() is not None, "nmap left running after quit"
assert any(t == "Scan in progress" for t, _ in seen), seen
print("GUI SMOKE OK")
