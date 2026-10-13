"""Check for Updates end to end against a fake GitHub: quiet start-up check, the dialog
text, the download with checksum verification, and the hand-over to apply_update."""
import hashlib
import json
import shutil
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from _harness import scratch, make_pump, stub_dialogs
import os

out = scratch("gui_update"); shutil.rmtree(out, ignore_errors=True); out.mkdir()
package = b"PK fake package " * 3000
NAMES = ["CybXNetworkLens-Setup-9.9.9.exe", "CybXNetworkLens-9.9.9-macos-arm64.dmg",
         "CybXNetworkLens-9.9.9-macos-x86_64.dmg", "CybXNetworkLens-9.9.9-linux-x86_64.tar.gz",
         "CybXNetworkLens-9.9.9-linux-aarch64.tar.gz"]
sums = "".join(hashlib.sha256(package).hexdigest() + f"  {n}\n" for n in NAMES)
body = "## Downloads\n\n| a | b |\n|---|---|\n| x | y |\n\n## What's Changed\n* Faster scans by @me in https://x/pull/1\n"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path.endswith("/releases/latest"):
            assets = [{"name": n, "browser_download_url": f"http://127.0.0.1:{port}/dl/pkg", "size": len(package)} for n in NAMES]
            assets.append({"name": "SHA256SUMS", "browser_download_url": f"http://127.0.0.1:{port}/dl/sums", "size": len(sums)})
            data = json.dumps({"tag_name": "v9.9.9", "body": body, "html_url": "http://example/rel", "assets": assets}).encode()
        elif self.path == "/dl/pkg":
            data = package
        else:
            data = sums.encode()
        self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)


srv = HTTPServer(("127.0.0.1", 0), H); port = srv.server_port
threading.Thread(target=srv.serve_forever, daemon=True).start()
os.environ["CYBX_UPDATE_API"] = f"http://127.0.0.1:{port}"
import tkinter as tk, gui, updater, webbrowser
seen = stub_dialogs(answer_yes=True)
opened = []
webbrowser.open = lambda url: opened.append(url)
root = tk.Tk(); app = gui.ScannerGUI(root); app.output_dir = out
pump = make_pump(root)
assert root.title().endswith(gui.__version__)

# start-up check: status bar only, no dialog
assert pump(lambda: "Update available" in app.status_var.get(), 15), app.status_var.get()
assert not seen

# a copy that can't replace itself: dialog -> releases page
updater.can_self_update = lambda: False
app.check_for_updates()
assert pump(lambda: bool(opened), 15), (seen, opened)
title, msg = seen[-1]
assert title == "Update available" and "can't update itself" in msg
assert "What's new:" in msg and "• Faster scans" in msg and "|" not in msg and "Downloads" not in msg, msg

# an installed copy: download, verify, apply, close
updater.can_self_update = lambda: True
applied = []
updater.apply_update = lambda p: applied.append(p)
destroyed = []
real_destroy = root.destroy
root.destroy = lambda: destroyed.append(1) or real_destroy()
app.check_for_updates()
assert pump(lambda: bool(applied) and bool(destroyed), 30), (seen[-1], app.status_var.get())
assert open(applied[0], "rb").read() == package
assert "Download and install it now" in seen[-1][1]
print("GUI UPDATE OK")
