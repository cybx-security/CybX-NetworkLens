"""Stop mid-scan keeps the finished host - driven by a fake nmap so timing is deterministic."""
import shutil
import threading
from pathlib import Path
from _harness import scratch, make_pump, stub_dialogs
import tkinter as tk
import gui

out = scratch("gui_partial"); shutil.rmtree(out, ignore_errors=True); out.mkdir()
stub_dialogs()
PARTIAL_XML = ('<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -sT -p 22,80 10.0.0.1 10.0.0.2" version="7.95" startstr="now">'
               '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><ports>'
               '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host>'
               '<host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="ope')


class FakeNmap:
    """Writes one finished host to -oX, streams a few lines, then hangs until killed."""
    def __init__(self, cmd, **kw):
        Path(cmd[cmd.index("-oX") + 1]).write_text(PARTIAL_XML)
        self._done = threading.Event(); self.returncode = None; self.pid = 4242
        def lines():
            yield "Starting Nmap 7.95\n"; yield "Nmap scan report for 10.0.0.1\n"; yield "Host is up.\n"
            self._done.wait()
        self.stdout = lines()
    def poll(self): return self.returncode
    def terminate(self): self.returncode = -15; self._done.set()
    kill = terminate
    def wait(self, timeout=None): self._done.wait(timeout); return self.returncode


gui.subprocess.Popen = FakeNmap
root = tk.Tk(); app = gui.ScannerGUI(root); app.output_dir = out
app.config["output"]["insights_events"] = {"enabled": True, "path": str(out / "feed.ndjson")}
pump = make_pump(root)
logtext = lambda: app.log.get("1.0", "end")
app.target_var.set("10.0.0.1 10.0.0.2"); app.mode_var.set("quick"); app._apply_mode()
assert "Expected duration" in app.estimate_var.get(), app.estimate_var.get()
app.start_scan()
assert pump(lambda: "Nmap scan report for 10.0.0.1" in logtext(), 20), logtext()[-500:]
app.stop_scan()
assert pump(lambda: not app._scan_running() and app.event_queue.empty(), 30)
print("status:", app.status_var.get())
assert "partial" in app.status_var.get().lower(), app.status_var.get()
assert app.last_output["scan_metadata"].get("partial") is True and app.last_output["scan_metadata"]["hosts_up"] == 1
files = sorted(p.name for p in out.iterdir()); print(files)
assert any(f.endswith(".json") for f in files) and any(f.endswith(".html") for f in files)
assert "feed.ndjson" not in files, "partial must not feed Insights"
assert "partial" in app.hist_tree.item(app.hist_tree.get_children()[0], "values")[2]
app.on_close()
print("PARTIAL OK")
