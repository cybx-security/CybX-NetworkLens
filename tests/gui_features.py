"""History, compare, HTML export, Settings (incl. the Insights feed controls), scheduling, support bundle."""
import copy
import json
import shutil
import zipfile
from pathlib import Path
from _harness import scratch, make_pump, stub_dialogs, ROOT
import tkinter as tk
from tkinter import filedialog
import gui
import paths

out = scratch("gui_features"); shutil.rmtree(out, ignore_errors=True); out.mkdir()
SAMPLE = ROOT / "tests" / "sample_report.json"
base = json.load(open(SAMPLE))
for i, ts in enumerate(("2026-10-01T10:00:00", "2026-10-02T10:00:00")):
    r = copy.deepcopy(base); r["scan_metadata"]["timestamp"] = ts
    if i == 1:
        r["hosts"][0]["ports"].append({"port": 23, "protocol": "tcp", "state": "open", "service": "telnet",
                                       "product": "", "version": "", "extra_info": "", "vulnerabilities": [], "scripts": []})
    json.dump(r, open(out / f"scan_127-0-0-1_2026100{i+1}_100000.json", "w"))
seen = stub_dialogs(answer_yes=False)
cfg_path = out / "config.json"
paths.config_write_path = lambda: cfg_path
root = tk.Tk(); app = gui.ScannerGUI(root); app.output_dir = out
pump = make_pump(root)
pump(timeout=0.5)
assert pump(lambda: bool(app.local_networks), 20), "network detection"
assert app.target_var.get(), "target pre-filled"
print("detected:", app.my_network_var.get(), "|", app.estimate_var.get())

pump(timeout=1.0)  # let the start-up history refresh settle before reading item ids
app.refresh_history(); kids = app.hist_tree.get_children(); assert len(kids) == 2
assert app.hist_tree.item(kids[0], "values")[5].endswith("20261002_100000.json"), "newest first"
app.hist_tree.selection_set(kids[0]); app.open_history_item(); pump()
assert app.last_output["scan_metadata"]["timestamp"].startswith("2026-10-02")
kids = app.hist_tree.get_children()
app.hist_tree.selection_set(kids[1]); app.compare_history_item(); pump()
assert "opened 23/tcp" in app.diff_text.get("1.0", "end")

filedialog.asksaveasfilename = lambda **k: str(out / "export.html")
app.export_html_report(); pump()
assert "Executive summary" in (out / "export.html").read_text()

# Settings: the feed path shows the default, Copy puts it on the clipboard, Browse+Save stores a custom one
app.open_settings_dialog(); pump()
dlg = [w for w in root.winfo_children() if isinstance(w, tk.Toplevel)][-1]
def widgets(kind, node):
    found = []
    for w in node.winfo_children():
        if isinstance(w, kind): found.append(w)
        found += widgets(kind, w)
    return found
entries = widgets(tk.ttk.Entry, dlg)
feed_entry = entries[1]
assert feed_entry.get() == str(paths.default_insights_feed_path()), feed_entry.get()
buttons = {b["text"]: b for b in widgets(tk.ttk.Button, dlg)}
buttons["Copy path"].invoke(); pump()
assert root.clipboard_get() == str(paths.default_insights_feed_path()), "copy button"
filedialog.asksaveasfilename = lambda **k: str(out / "feed.ndjson")
buttons["Browse..."].invoke(); pump()
assert feed_entry.get().endswith("feed.ndjson")
buttons["Save"].invoke(); pump()
saved = json.load(open(cfg_path)); assert saved["output"]["insights_events"]["path"].endswith("feed.ndjson"), saved
# Default button -> stored as "" (follow the default)
app.open_settings_dialog(); pump()
dlg = [w for w in root.winfo_children() if isinstance(w, tk.Toplevel)][-1]
buttons = {b["text"]: b for b in widgets(tk.ttk.Button, dlg)}
buttons["Default"].invoke(); pump(); buttons["Save"].invoke(); pump()
assert json.load(open(cfg_path))["output"]["insights_events"]["path"] == ""
assert not [s for s in seen if s[0].startswith("Couldn't")], seen

app.open_schedule_dialog(); pump()
dlg = [w for w in root.winfo_children() if isinstance(w, tk.Toplevel)][-1]
buttons = {b["text"]: b for b in widgets(tk.ttk.Button, dlg)}
buttons["Save schedule"].invoke(); pump()
assert any("source" in m for _, m in seen), seen
dlg.destroy()

filedialog.asksaveasfilename = lambda **k: str(out / "support.zip")
app.save_support_info(); pump()
names = zipfile.ZipFile(out / "support.zip").namelist(); assert "environment.txt" in names and "live_log.txt" in names

app.use_my_network(); pump()
if len(app.local_networks) > 1:
    dlg = [w for w in root.winfo_children() if isinstance(w, tk.Toplevel)][-1]
    widgets(tk.ttk.Button, dlg)[0].invoke(); pump()
assert app.target_var.get() == app.local_networks[0].suggested_target
app.on_close()
print("FEATURES OK")
