"""
Tkinter GUI for the CybX NetworkLens.

Runs entirely on stdlib (tkinter) so it bundles cleanly with PyInstaller
and adds no runtime dependencies. The scan executes in a worker thread;
nmap's verbose output is streamed back to the GUI via a thread-safe queue
and parsed for progress percentages.
"""

import csv
import json
from datetime import datetime
import os
import platform
import queue
import re
import subprocess
import sys
import tempfile
import threading
import webbrowser
from pathlib import Path
from typing import Any, Dict, Optional

import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, messagebox, scrolledtext, ttk

try:
    from scanner import (build_nmap_command, check_privileges, get_nmap_version,
                         nmap_environment_warnings, exit_code_hint, rate_limit_warning,
                         format_command, NO_WINDOW_FLAGS)
    from scan_profile import GENTLE_SCAN
    from parser import parse_nmap_xml, nmap_run_error
    from local_analyzer import analyze_locally
    from output import (create_insights_report, generate_filename,
                        create_nmap_chat_events, write_ndjson_events,
                        write_json_output)
    from main import load_config
    from npcap import (is_windows, is_npcap_installed, find_bundled_installer, install_npcap,
                       NPCAP_DOWNLOAD_URL)
    from diff import diff_reports, format_diff_lines, load_report
    from parser import port_dict_is_open
    from paths import resolve_output_dir, icon_path, claim_for_owner, save_config, config_write_path
    from version import __version__
    import updater
    from elevate import relaunch_elevated
    from scan_profile import estimate_mode_seconds, format_estimate
    from parser import salvage_partial_xml
    import netinfo
    import report_html
    import scheduled
    import diagnostics
    import ui_theme
except ImportError:
    from .scanner import (build_nmap_command, check_privileges, get_nmap_version,
                          nmap_environment_warnings, exit_code_hint, rate_limit_warning,
                          format_command, NO_WINDOW_FLAGS)
    from .scan_profile import GENTLE_SCAN
    from .parser import parse_nmap_xml, nmap_run_error
    from .local_analyzer import analyze_locally
    from .output import (create_insights_report, generate_filename,
                         create_nmap_chat_events, write_ndjson_events,
                         write_json_output)
    from .main import load_config
    from .npcap import (is_windows, is_npcap_installed, find_bundled_installer, install_npcap,
                        NPCAP_DOWNLOAD_URL)
    from .diff import diff_reports, format_diff_lines, load_report
    from .parser import port_dict_is_open
    from .paths import resolve_output_dir, icon_path, claim_for_owner, save_config, config_write_path
    from .version import __version__
    from . import updater
    from .elevate import relaunch_elevated
    from .scan_profile import estimate_mode_seconds, format_estimate
    from .parser import salvage_partial_xml
    from . import netinfo
    from . import report_html
    from . import scheduled
    from . import diagnostics
    from . import ui_theme


PROGRESS_RE = re.compile(r"About ([\d.]+)% done", re.IGNORECASE)
HOST_DISCOVERED_RE = re.compile(r"Nmap scan report for (.+)")


class ScannerGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(f"CybX NetworkLens {__version__}")
        # Pixel sizes below are designed for 96 dpi; scale them on high-DPI
        # Windows screens (Tk scales fonts itself, not widget geometry).
        self.scale = 1.0
        if platform.system() == "Windows":
            try:
                self.scale = max(1.0, root.winfo_fpixels("1i") / 96.0)
            except tk.TclError:
                pass
        self.root.geometry(f"{self.px(1000)}x{self.px(750)}")
        self.root.minsize(self.px(800), self.px(600))
        self._actions: Dict[str, list] = {}
        self.local_networks: list = []

        self.event_queue: "queue.Queue[tuple]" = queue.Queue()
        self.proc: Optional[subprocess.Popen] = None
        self.scan_thread: Optional[threading.Thread] = None
        self.xml_tmp_path: Optional[str] = None
        self.last_output: Optional[Dict[str, Any]] = None
        self.last_saved_report: Optional[str] = None
        self.last_events: Optional[list] = None
        # Set by Stop/Quit so the worker reports "stopped" rather than treating
        # the half-written XML of a killed nmap as a failed scan.
        self._stop_requested = False
        self._update_in_progress = False

        # Config messages are held and replayed into the log once it exists:
        # a windowed build has no console for load_config to print to.
        config_messages: list = []
        try:
            self.config = load_config(log=config_messages.append)
        except Exception as e:
            self.config = {}
            config_messages.append(f"[!] Warning: Could not load configuration: {e}")
        self.output_dir = resolve_output_dir(self.config.get("output", {}).get("directory"))

        self._set_window_icon()
        self.palette = ui_theme.PALETTES["light"]
        self._apply_theme()
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        for msg in config_messages:
            self._log(msg, "warn" if msg.startswith("[!]") else "info")
        self._log(f"[*] Reports are saved to: {self.output_dir}", "info")
        self._show_environment()
        self.root.after(300, self._detect_network)
        self.root.after(600, self.refresh_history)
        # Run the Npcap check after the window is on screen so the user sees the
        # GUI before any modal dialog appears.
        self.root.after(200, self._check_npcap)
        if self.config.get("updates", {}).get("check_on_startup", True):
            self.root.after(1500, lambda: self.check_for_updates(quiet=True))
        self._poll_queue()

    # ---------- UI construction ----------

    def px(self, n: int) -> int:
        """A 96-dpi pixel size scaled for this screen."""
        return int(round(n * self.scale))

    def _register(self, name: str, *controls) -> None:
        """Buttons and menu entries that enable/disable together."""
        self._actions.setdefault(name, []).extend(controls)

    def _enable(self, name: str, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        for control in self._actions.get(name, []):
            try:
                if isinstance(control, tuple):   # (menu, label)
                    control[0].entryconfig(control[1], state=state)
                else:
                    control.config(state=state)
            except tk.TclError:
                pass

    def _build_menu(self) -> None:
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="Open Report...", command=self.open_report)
        file_menu.add_command(label="Save Report (JSON)...", command=self.save_report)
        file_menu.add_command(label="Export Report (HTML)...", command=self.export_html_report)
        file_menu.add_command(label="Export Inventory (CSV)...", command=self.export_inventory_csv)
        file_menu.add_command(label="Save Insights Events...", command=self.save_events)
        file_menu.add_separator()
        file_menu.add_command(label="Open Output Folder", command=self.open_output_folder)
        file_menu.add_separator()
        file_menu.add_command(label="Quit", command=self.on_close)
        menubar.add_cascade(label="File", menu=file_menu)
        self._register("save", (file_menu, "Save Report (JSON)..."), (file_menu, "Export Report (HTML)..."),
                       (file_menu, "Export Inventory (CSV)..."))
        self._register("events", (file_menu, "Save Insights Events..."))

        tools = tk.Menu(menubar, tearoff=False)
        tools.add_command(label="Compare with Previous Scan...", command=self.compare_with_previous)
        tools.add_command(label="Scheduled Scan...", command=self.open_schedule_dialog)
        tools.add_command(label="Settings...", command=self.open_settings_dialog)
        tools.add_separator()
        tools.add_command(label="Check for Updates...", command=self.check_for_updates)
        tools.add_command(label="Save Support Info...", command=self.save_support_info)
        menubar.add_cascade(label="Tools", menu=tools)
        self._register("compare", (tools, "Compare with Previous Scan..."))

        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(label="User Guide (online)",
                              command=lambda: webbrowser.open(f"https://github.com/{updater.REPO}#readme"))
        help_menu.add_command(label="Releases & Downloads", command=lambda: webbrowser.open(updater.RELEASES_PAGE))
        help_menu.add_command(label="About", command=lambda: messagebox.showinfo(
            "About", f"CybX NetworkLens {__version__}\n\nFinds the devices on a network, lists their open "
                     "ports and services, and flags the risky ones.\n\nhttps://github.com/" + updater.REPO))
        menubar.add_cascade(label="Help", menu=help_menu)
        self.root.config(menu=menubar)

    def _set_window_icon(self) -> None:
        """Title-bar/taskbar icon. Cosmetic, so any failure is ignored."""
        try:
            if platform.system() == "Windows":
                ico = icon_path("ico")
                if ico:
                    self.root.iconbitmap(default=str(ico))
            else:
                png = icon_path("png")
                if png:
                    self._icon_image = tk.PhotoImage(file=str(png))
                    self.root.iconphoto(True, self._icon_image)
        except Exception:
            pass

    def _mono(self, size: int, *extra) -> tuple:
        family = "Menlo" if platform.system() == "Darwin" else ("Consolas" if platform.system() == "Windows" else "DejaVu Sans Mono")
        return (family, size) + extra

    def _apply_theme(self, preference: Optional[str] = None) -> None:
        """Switch light/dark and recolour the classic tk widgets to match."""
        pref = preference or self.config.get("ui", {}).get("theme", "system")
        self.theme_name = ui_theme.resolve(pref)
        self.palette = ui_theme.apply(self.root, self.theme_name)
        pal = self.palette
        for widget in getattr(self, "_text_widgets", []):
            try:
                widget.configure(background=pal["card"], foreground=pal["fg"],
                                 insertbackground=pal["fg"], selectbackground=pal["select"],
                                 highlightthickness=0, borderwidth=0, relief="flat")
            except tk.TclError:
                pass
        if hasattr(self, "log"):
            for tag in ("info", "warn", "error", "ok", "cmd"):
                self.log.tag_configure(tag, foreground=pal[tag])
            for tag in ("critical", "high", "medium", "low", "info"):
                self.tree.tag_configure(tag, foreground=pal[tag])
                self.hist_tree.tag_configure(tag, foreground=pal[tag])
            for tag in ("add", "remove", "change", "ok", "info"):
                self.diff_text.tag_configure(tag, foreground=pal[tag])
            self.diff_text.tag_configure("header", foreground=pal["fg"])
            for lbl in getattr(self, "_muted_labels", []):
                try:
                    lbl.configure(foreground=pal["muted"])
                except tk.TclError:
                    pass
            for lbl in getattr(self, "_accent_labels", []):
                try:
                    lbl.configure(foreground=pal["accent"])
                except tk.TclError:
                    pass

    def _muted(self, parent, **kw) -> ttk.Label:
        lbl = ttk.Label(parent, foreground=self.palette["muted"], **kw)
        self._muted_labels.append(lbl)
        return lbl

    def _build_ui(self) -> None:
        self._text_widgets: list = []
        self._muted_labels: list = []
        self._accent_labels: list = []
        self._build_menu()
        base = tkfont.nametofont("TkDefaultFont")
        self.font_title = tkfont.Font(family=base.actual("family"), size=base.actual("size") + 7, weight="bold")
        self.font_heading = tkfont.Font(family=base.actual("family"), size=base.actual("size") + 2, weight="bold")
        self.font_small = tkfont.Font(family=base.actual("family"), size=max(9, base.actual("size") - 1))
        pad = self.px(12)

        # ---- Header: who we are, and whether this run has full rights ----
        header = ttk.Frame(self.root, padding=(pad + 4, pad, pad + 4, 4))
        header.pack(fill="x")
        title_box = ttk.Frame(header)
        title_box.pack(side="left")
        ttk.Label(title_box, text="CybX NetworkLens", font=self.font_title).pack(anchor="w")
        self._muted(title_box, text=f"Version {__version__}  ·  find devices, open ports and risky services",
                    font=self.font_small).pack(anchor="w")
        header_right = ttk.Frame(header)
        header_right.pack(side="right")
        self.priv_var = tk.StringVar(value="")
        self.priv_label = ttk.Label(header_right, textvariable=self.priv_var, font=self.font_small)
        self.priv_label.pack(side="right", padx=(8, 0))
        ttk.Button(header_right, text="Settings", command=self.open_settings_dialog).pack(side="right", padx=4)
        self.update_btn = ttk.Button(header_right, text="Check for Updates", command=self.check_for_updates)
        self.update_btn.pack(side="right", padx=4)

        # ---- Body: setup card on the left, results on the right ----
        body = ttk.Frame(self.root, padding=(pad, 4, pad, 0))
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        card = ttk.Frame(body, style="Card.TFrame", padding=pad + 2)
        card.grid(row=0, column=0, sticky="nsw", padx=(0, pad))
        form = card  # the attribute name the rest of the class uses
        ttk.Label(form, text="Scan setup", font=self.font_heading).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))

        ttk.Label(form, text="Target").grid(row=1, column=0, sticky="w", pady=(4, 2))
        self.target_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.target_var, width=30).grid(row=1, column=1, sticky="we", pady=(4, 2))
        target_side = ttk.Frame(form)
        target_side.grid(row=2, column=0, columnspan=2, sticky="we")
        self.my_network_btn = ttk.Button(target_side, text="Use my network", command=self.use_my_network,
                                         state="disabled")
        self.my_network_btn.pack(side="left")
        self.my_network_var = tk.StringVar(value="finding your network...")
        self._muted(target_side, textvariable=self.my_network_var, font=self.font_small,
                    wraplength=self.px(220), justify="left").pack(side="left", padx=8)

        # Scan mode
        ttk.Label(form, text="Mode").grid(row=3, column=0, sticky="w", pady=(12, 2))
        mode_frame = ttk.Frame(form)
        mode_frame.grid(row=3, column=1, sticky="w", pady=(12, 2))
        self.mode_var = tk.StringVar(value="full")
        for i, (value, label) in enumerate((("discover", "Discover"), ("quick", "Quick"),
                                            ("gentle", "Gentle"), ("full", "Full"))):
            ttk.Radiobutton(mode_frame, text=label, variable=self.mode_var, value=value,
                            command=self._apply_mode).pack(side="left", padx=(0 if i == 0 else 10, 0))
        self.mode_hint_var = tk.StringVar()
        self._muted(form, textvariable=self.mode_hint_var, font=self.font_small,
                    wraplength=self.px(300), justify="left").grid(row=4, column=0, columnspan=2, sticky="w")

        # Options as switches
        ttk.Label(form, text="Options", font=self.font_heading).grid(row=5, column=0, columnspan=2, sticky="w", pady=(14, 4))
        opts = ttk.Frame(form)
        opts.grid(row=6, column=0, columnspan=2, sticky="we")
        self.os_var = tk.BooleanVar(value=True)
        self.vuln_var = tk.BooleanVar(value=True)
        self.udp_var = tk.BooleanVar(value=True)
        self.os_cb = ttk.Checkbutton(opts, text="OS detection", variable=self.os_var, style="Switch.TCheckbutton")
        self.os_cb.grid(row=0, column=0, sticky="w", pady=2)
        self.vuln_cb = ttk.Checkbutton(opts, text="Vulnerability scripts", variable=self.vuln_var, style="Switch.TCheckbutton")
        self.vuln_cb.grid(row=1, column=0, sticky="w", pady=2)
        self.udp_cb = ttk.Checkbutton(opts, text="UDP services (SNMP, IPMI, TFTP)", variable=self.udp_var, style="Switch.TCheckbutton")
        self.udp_cb.grid(row=2, column=0, sticky="w", pady=2)

        adv = ttk.Frame(form)
        adv.grid(row=7, column=0, columnspan=2, sticky="we", pady=(8, 0))
        adv.columnconfigure(1, weight=1)
        ttk.Label(adv, text="Ports").grid(row=0, column=0, sticky="w", pady=2)
        self.ports_var = tk.StringVar()
        self.ports_entry = ttk.Entry(adv, textvariable=self.ports_var)
        self.ports_entry.grid(row=0, column=1, sticky="we", padx=(8, 0), pady=2)
        ttk.Label(adv, text="Exclude").grid(row=1, column=0, sticky="w", pady=2)
        self.exclude_var = tk.StringVar()
        ttk.Entry(adv, textvariable=self.exclude_var).grid(row=1, column=1, sticky="we", padx=(8, 0), pady=2)
        ttk.Label(adv, text="Timing").grid(row=2, column=0, sticky="w", pady=2)
        timing_row = ttk.Frame(adv)
        timing_row.grid(row=2, column=1, sticky="w", padx=(8, 0), pady=2)
        self.timing_var = tk.IntVar(value=4)
        self.timing_combo = ttk.Combobox(timing_row, textvariable=self.timing_var, values=[0, 1, 2, 3, 4, 5],
                                         width=3, state="readonly")
        self.timing_combo.pack(side="left")
        self._muted(timing_row, text="0 = slow & quiet, 5 = fast & loud", font=self.font_small).pack(side="left", padx=6)
        ttk.Label(adv, text="Max rate").grid(row=3, column=0, sticky="w", pady=2)
        rate_row = ttk.Frame(adv)
        rate_row.grid(row=3, column=1, sticky="w", padx=(8, 0), pady=2)
        self.max_rate_var = tk.StringVar()
        ttk.Entry(rate_row, textvariable=self.max_rate_var, width=7).pack(side="left")
        self._muted(rate_row, text="packets/sec, blank = no limit", font=self.font_small).pack(side="left", padx=6)
        self._muted(form, text="Ports: blank = recommended set, e.g. 22,80,443 or 1-1000. "
                               "Exclude: hosts to skip, e.g. 10.0.0.5, 10.0.0.9. "
                               "Lower the rate for fragile gear (PLCs, medical devices, printers).",
                    font=self.font_small, wraplength=self.px(300), justify="left").grid(
            row=8, column=0, columnspan=2, sticky="w", pady=(6, 0))

        # Expected duration + the big buttons
        self.estimate_var = tk.StringVar(value="")
        est = ttk.Label(form, textvariable=self.estimate_var, wraplength=self.px(300), justify="left",
                        foreground=self.palette["accent"])
        self._accent_labels.append(est)
        est.grid(row=9, column=0, columnspan=2, sticky="w", pady=(14, 6))
        for var in (self.target_var, self.mode_var, self.udp_var, self.max_rate_var, self.ports_var):
            var.trace_add("write", lambda *_: self._update_estimate())
        btns = ttk.Frame(form)
        btns.grid(row=10, column=0, columnspan=2, sticky="we", pady=(4, 0))
        self.start_btn = ttk.Button(btns, text="Start scan", style="Accent.TButton", command=self.start_scan)
        self.start_btn.pack(side="left", fill="x", expand=True)
        self.stop_btn = ttk.Button(btns, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=(8, 0))
        form.columnconfigure(1, weight=1)
        self._apply_mode()

        # ---- Right: results toolbar + tabs ----
        right = ttk.Frame(body)
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)
        toolbar = ttk.Frame(right)
        toolbar.grid(row=0, column=0, sticky="we", pady=(0, 6))
        self.save_btn = ttk.Button(toolbar, text="Save report", command=self.save_report, state="disabled")
        self.save_btn.pack(side="left")
        self.export_html_btn = ttk.Button(toolbar, text="Export HTML report", command=self.export_html_report,
                                          state="disabled")
        self.export_html_btn.pack(side="left", padx=6)
        self._register("save", self.save_btn, self.export_html_btn)
        ttk.Button(toolbar, text="Open output folder", command=self.open_output_folder).pack(side="left")
        ttk.Button(toolbar, text="Open report...", command=self.open_report).pack(side="right")

        nb = ttk.Notebook(right)
        nb.grid(row=1, column=0, sticky="nsew")
        self.nb = nb

        # Live log
        log_frame = ttk.Frame(nb, padding=6)
        self.log = scrolledtext.ScrolledText(log_frame, wrap="word", height=18, font=self._mono(11 if platform.system() == "Darwin" else 10))
        self.log.pack(fill="both", expand=True)
        self._text_widgets.append(self.log)
        self.log.tag_configure("cmd", font=self._mono(10 if platform.system() == "Darwin" else 9, "italic"))
        self.log.configure(state="disabled")
        nb.add(log_frame, text="  Live log  ")

        # Inventory — flat device table for on-site network audits
        inv_frame = ttk.Frame(nb, padding=6)
        self.inv_frame = inv_frame
        nb.add(inv_frame, text="  Inventory  ")
        inv_cols = ("ip", "hostname", "mac", "vendor", "ports", "os")
        self.inv_tree = ttk.Treeview(inv_frame, columns=inv_cols, show="headings")
        headings = {
            "ip": ("IP address", 130), "hostname": ("Hostname", 160), "mac": ("MAC address", 150),
            "vendor": ("Vendor", 140), "ports": ("Open ports (protocol/service)", 320), "os": ("OS guess", 160),
        }
        for col, (title, width) in headings.items():
            self.inv_tree.heading(col, text=title)
            self.inv_tree.column(col, width=self.px(width), stretch=(col == "ports"))
        inv_vsb = ttk.Scrollbar(inv_frame, orient="vertical", command=self.inv_tree.yview)
        inv_hsb = ttk.Scrollbar(inv_frame, orient="horizontal", command=self.inv_tree.xview)
        self.inv_tree.configure(yscrollcommand=inv_vsb.set, xscrollcommand=inv_hsb.set)
        self.inv_tree.grid(row=0, column=0, sticky="nsew")
        inv_vsb.grid(row=0, column=1, sticky="ns")
        inv_hsb.grid(row=1, column=0, sticky="we")
        inv_frame.rowconfigure(0, weight=1)
        inv_frame.columnconfigure(0, weight=1)
        self.only_found_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(inv_frame, text="Only show hosts with open ports", variable=self.only_found_var,
                        command=self._refilter, style="Switch.TCheckbutton").grid(
            row=2, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self.inv_note_var = tk.StringVar(value="")
        self._muted(inv_frame, textvariable=self.inv_note_var, font=self.font_small, wraplength=self.px(600),
                    justify="left").grid(row=3, column=0, columnspan=2, sticky="w", pady=(4, 0))

        # Results
        results_frame = ttk.Frame(nb, padding=6)
        nb.add(results_frame, text="  Results  ")
        self.summary_box = tk.Text(results_frame, height=8, wrap="word", font=base)
        self.summary_box.insert("1.0", "No scan run yet.")
        self.summary_box.configure(state="disabled")
        self.summary_box.pack(fill="x", pady=(0, 6))
        self._text_widgets.append(self.summary_box)
        ttk.Checkbutton(results_frame, text="Only show hosts with open ports", variable=self.only_found_var,
                        command=self._refilter, style="Switch.TCheckbutton").pack(anchor="w", pady=(0, 6))
        tree_wrap = ttk.Frame(results_frame)
        tree_wrap.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tree_wrap, columns=("detail",), show="tree headings")
        self.tree.heading("#0", text="Item")
        self.tree.heading("detail", text="Detail / risk")
        self.tree.column("#0", width=self.px(420), stretch=True)
        self.tree.column("detail", width=self.px(420), stretch=True)
        vsb = ttk.Scrollbar(tree_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # Changes — diff against a previous scan of the same network
        diff_frame = ttk.Frame(nb, padding=6)
        self.diff_frame = diff_frame
        self.diff_text = scrolledtext.ScrolledText(diff_frame, wrap="word", height=18, font=self._mono(11 if platform.system() == "Darwin" else 10))
        self.diff_text.pack(fill="both", expand=True)
        self._text_widgets.append(self.diff_text)
        self.diff_text.tag_configure("header", font=self._mono(11 if platform.system() == "Darwin" else 10, "bold"))
        self.diff_text.insert("1.0", "Run or open a scan, then use Tools > Compare with Previous Scan "
                                     "(or the History tab) and pick an older report of the same network.")
        self.diff_text.configure(state="disabled")
        nb.add(diff_frame, text="  Changes  ")

        # History — every report in the output folder, newest first
        hist = ttk.Frame(nb, padding=6)
        nb.add(hist, text="  History  ")
        hist_cols = ("when", "target", "type", "hosts", "risk", "file")
        self.hist_tree = ttk.Treeview(hist, columns=hist_cols, show="headings", selectmode="browse")
        for col, title, width in (("when", "Scanned", 150), ("target", "Target", 170), ("type", "Type", 100),
                                  ("hosts", "Hosts up", 70), ("risk", "Risk", 80), ("file", "File", 320)):
            self.hist_tree.heading(col, text=title)
            self.hist_tree.column(col, width=self.px(width), stretch=(col == "file"))
        hist_vsb = ttk.Scrollbar(hist, orient="vertical", command=self.hist_tree.yview)
        self.hist_tree.configure(yscrollcommand=hist_vsb.set)
        self.hist_tree.grid(row=0, column=0, sticky="nsew")
        hist_vsb.grid(row=0, column=1, sticky="ns")
        hist.rowconfigure(0, weight=1)
        hist.columnconfigure(0, weight=1)
        hist_btns = ttk.Frame(hist)
        hist_btns.grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Button(hist_btns, text="Open", command=self.open_history_item).pack(side="left")
        ttk.Button(hist_btns, text="Compare current with selected", command=self.compare_history_item).pack(side="left", padx=6)
        ttk.Button(hist_btns, text="Export as HTML...", command=self.export_history_item).pack(side="left")
        ttk.Button(hist_btns, text="Refresh", command=self.refresh_history).pack(side="left", padx=6)
        self.hist_tree.bind("<Double-1>", lambda _e: self.open_history_item())
        self.hist_note_var = tk.StringVar(value="")
        self._muted(hist, textvariable=self.hist_note_var, font=self.font_small).grid(
            row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))

        # Raw JSON
        json_frame = ttk.Frame(nb, padding=6)
        self.json_text = scrolledtext.ScrolledText(json_frame, wrap="none", height=18, font=self._mono(10 if platform.system() == "Darwin" else 9))
        self.json_text.pack(fill="both", expand=True)
        self._text_widgets.append(self.json_text)
        nb.add(json_frame, text="  Raw JSON  ")

        # ---- Status bar ----
        status = ttk.Frame(self.root, padding=(pad, 6, pad, 8))
        status.pack(fill="x", side="bottom")
        self.progress = ttk.Progressbar(status, mode="indeterminate", length=self.px(220))
        self.progress.pack(side="left")
        self.status_var = tk.StringVar(value="Ready. Pick a target and click Start scan.")
        ttk.Label(status, textvariable=self.status_var).pack(side="left", padx=10)

        self._apply_theme()

    MODE_HINTS = {
        "discover": "Discover = ping sweep: who is alive. Seconds, no ports probed.",
        "quick": "Quick = ports + services only. Fast sweep.",
        "gentle": "Gentle = rate-capped, one probe at a time, no OS/vuln/UDP. "
                  "For fragile gear. Much slower.",
        "full": "Full = + OS, UDP, scripts, CVEs, traceroute.",
    }

    def _update_estimate(self) -> None:
        target = self.target_var.get().strip()
        if not target:
            self.estimate_var.set("")
            return
        mode = self.mode_var.get()
        rate = None
        try:
            rate = int(self.max_rate_var.get().strip() or 0) or None
        except ValueError:
            pass
        if self.ports_var.get().strip() and mode != "discover":
            self.estimate_var.set("Custom port list: duration depends on how many ports you chose.")
            return
        if rate and mode != "gentle":
            seconds = rate_limit_warning  # noqa: F841 (use the exact arithmetic below)
            try:
                from scan_profile import estimate_scan_seconds, balanced_tcp_ports
            except ImportError:
                from .scan_profile import estimate_scan_seconds, balanced_tcp_ports
            seconds = estimate_scan_seconds(target, len(balanced_tcp_ports()), rate)
        else:
            seconds = estimate_mode_seconds(mode, target, self.udp_var.get(), rate)
        if seconds is None:
            self.estimate_var.set("")
            return
        self.estimate_var.set(f"Expected duration: {format_estimate(seconds)} "
                              "(depends on how many devices answer)")

    def _apply_mode(self) -> None:
        """Preset the detailed toggles and rate cap from the selected scan mode."""
        mode = self.mode_var.get()
        self.mode_hint_var.set(self.MODE_HINTS.get(mode, ""))

        # A ping sweep probes no ports, so the port/feature controls have no
        # effect. Grey them out rather than letting them imply otherwise.
        port_state = "disabled" if mode == "discover" else "normal"
        self.ports_entry.config(state=port_state)
        self.os_cb.config(state=port_state)
        self.vuln_cb.config(state=port_state)
        self.udp_cb.config(state=port_state)
        self.timing_combo.config(state="disabled" if mode == "discover" else "readonly")

        if mode == "discover":
            self.timing_var.set(4)
            return

        if mode == "gentle":
            # Everything the gentle preset dictates; the user can still override
            # any individual toggle afterwards.
            self.os_var.set(GENTLE_SCAN["os_detection"])
            self.vuln_var.set(GENTLE_SCAN["vulnerability_scan"])
            self.udp_var.set(GENTLE_SCAN["udp_scan"])
            self.timing_var.set(GENTLE_SCAN["timing"])
            self.max_rate_var.set(str(GENTLE_SCAN["max_rate"]))
            return

        full = mode == "full"
        self.os_var.set(full)
        self.vuln_var.set(full)
        self.udp_var.set(full)
        # Leaving gentle mode: restore normal timing and drop the rate cap, so
        # a Full scan doesn't silently inherit a 50 pps brake.
        self.timing_var.set(4)
        if self.max_rate_var.get() == str(GENTLE_SCAN["max_rate"]):
            self.max_rate_var.set("")

    def _show_environment(self) -> None:
        ver = get_nmap_version()
        if ver:
            self._log(f"[*] {ver}", "info")
        else:
            self._log("[!] nmap binary not found. Drop one into binaries/<os>/ "
                      "or install it on the system before starting a scan.", "error")
        for warning in nmap_environment_warnings():
            self._log(f"[!] {warning}", "warn")
        if not check_privileges():
            self._log("[!] Not running with root/administrator privileges. "
                      "OS detection, SYN scan, and some vuln scripts will fail.", "warn")
            self._log("    Restart the app and enter your password when asked (macOS/Linux), "
                      "or use 'Run as Administrator' (Windows).", "warn")
            self.priv_var.set("Limited rights - TCP-connect scans only")
            self.priv_label.configure(foreground=self.palette["warn"])
        elif is_windows() and not is_npcap_installed():
            self._log("[!] Npcap is not installed, so scans fall back to TCP-connect mode: "
                      "no SYN scan, OS detection, or UDP until it is.", "warn")
            self.priv_var.set("Npcap missing - TCP-connect scans only")
            self.priv_label.configure(foreground=self.palette["warn"])
        else:
            self.priv_var.set("Full scan rights")
            self.priv_label.configure(foreground=self.palette["ok"])

    def _detect_network(self) -> None:
        """Find the machine's own network in the background and offer it as the target."""
        def worker() -> None:
            try:
                nets = netinfo.local_networks()
            except Exception:
                nets = []
            self.event_queue.put(("networks", nets))
        threading.Thread(target=worker, daemon=True).start()

    def _handle_networks(self, nets: list) -> None:
        self.local_networks = nets
        if not nets:
            self.my_network_var.set("couldn't work out your network - type a target")
            return
        best = nets[0]
        note = best.label
        if best.is_trimmed:
            note += f" (your network is {best.network}; the /24 around you is offered)"
        if best.virtual:
            note += " - a virtual adapter; on a VM use Bridged networking"
        self.my_network_var.set(note)
        self.my_network_btn.config(state="normal")
        if not self.target_var.get().strip():
            self.target_var.set(best.suggested_target)
            self._log(f"[*] Your network looks like {best.suggested_target} ({best.interface}); "
                      "it has been filled in as the target.", "info")

    def use_my_network(self) -> None:
        if not self.local_networks:
            return
        if len(self.local_networks) == 1:
            self.target_var.set(self.local_networks[0].suggested_target)
            return
        # More than one network: let the user pick.
        win = tk.Toplevel(self.root)
        win.title("Which network?")
        win.transient(self.root)
        ttk.Label(win, text="This computer is on more than one network:", padding=10).pack(anchor="w")
        choice = tk.StringVar(value=self.local_networks[0].suggested_target)
        for n in self.local_networks:
            ttk.Radiobutton(win, text=n.label, variable=choice, value=n.suggested_target).pack(anchor="w", padx=20)
        def ok() -> None:
            self.target_var.set(choice.get())
            win.destroy()
        ttk.Button(win, text="Use this network", command=ok).pack(pady=10)
        win.grab_set()

    def _check_npcap(self) -> None:
        """On Windows, prompt the user to install Npcap if it's missing."""
        if not is_windows() or is_npcap_installed():
            if is_windows():
                self._log("[*] Npcap is installed.", "ok")
            return

        self._log("[!] Npcap is not installed on this machine.", "warn")
        self._log("    Npcap is required for SYN scan, OS detection, and most vuln scripts.", "warn")

        installer = find_bundled_installer()
        if installer is None:
            self._log(f"    Get it from {NPCAP_DOWNLOAD_URL} - until then scans run in the "
                      "slower TCP-connect mode without OS detection or UDP.", "warn")
            if messagebox.askyesno(
                    "Install Npcap?",
                    "Npcap (a free packet-capture driver) is needed for full scans: SYN scan, "
                    "OS detection, and UDP services like SNMP.\n\n"
                    "Open the Npcap download page in your browser? Run the installer it "
                    "gives you, then restart the scanner."):
                webbrowser.open(NPCAP_DOWNLOAD_URL)
            return

        proceed = messagebox.askyesno(
            "Install Npcap?",
            "Npcap is required for full network scanning capabilities "
            "(SYN scan, OS detection, vuln scripts).\n\n"
            f"A bundled installer is available:\n  {installer.name}\n\n"
            "Install it now? The Npcap setup window will open - click through "
            "it (Next, then Install) and come back here when it finishes.",
        )
        if not proceed:
            self._log("    Skipped. You can install Npcap later from https://npcap.com", "warn")
            return

        self._log("[*] Opening Npcap setup - finish it in the window that appears...", "info")
        self.status_var.set("Waiting for Npcap setup to finish...")
        self.start_btn.config(state="disabled")

        # The installer blocks until its window is closed; waiting on the Tk
        # thread would freeze this window ("Not Responding") the whole time.
        def worker() -> None:
            try:
                ok, msg = install_npcap(
                    installer, on_log=lambda m: self.event_queue.put(("line", f"    {m}")))
            except Exception as e:
                ok, msg = False, f"Npcap install failed: {e}"
            self.event_queue.put(("npcap_done", (ok, msg)))

        threading.Thread(target=worker, daemon=True).start()

    def _handle_npcap_done(self, result: tuple) -> None:
        ok, msg = result
        self.start_btn.config(state="normal")
        if ok:
            self._log(f"[+] {msg}", "ok")
            self.status_var.set("Npcap installed. Ready to scan.")
        else:
            self._log(f"[!] {msg}", "error")
            self._log("    You can also install manually from https://npcap.com", "warn")
            self.status_var.set("Npcap is not installed - scans will be limited.")

    # ---------- Logging ----------

    def _log(self, line: str, tag: str = "info") -> None:
        self.log.configure(state="normal")
        self.log.insert("end", line + "\n", tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    # ---------- Scan lifecycle ----------

    def start_scan(self) -> None:
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("Missing target", "Enter a target (IP, range, or CIDR) before starting.")
            return
        if self.scan_thread and self.scan_thread.is_alive():
            return

        # Validate the rate cap before anything else — a typo here would
        # otherwise reach nmap as a malformed argument and abort the scan.
        raw_rate = self.max_rate_var.get().strip()
        max_rate = None
        if raw_rate:
            try:
                max_rate = int(raw_rate)
                if max_rate <= 0:
                    raise ValueError
            except ValueError:
                messagebox.showwarning(
                    "Invalid max rate",
                    f"Max rate must be a whole number of packets per second (got {raw_rate!r}).\n\n"
                    "Leave it blank for no limit.")
                return

        mode = self.mode_var.get()
        gentle = mode == "gentle"
        discovery = mode == "discover"
        # One probe in flight is what makes a gentle scan gentle; without it the
        # rate cap alone still lets nmap burst against a single fragile device.
        max_parallelism = GENTLE_SCAN["max_parallelism"] if gentle else None

        # A ping sweep probes no ports, so the port-count-based estimate doesn't apply.
        warning = None if discovery else rate_limit_warning(
            target, max_rate, self.ports_var.get().strip() or None, self.udp_var.get())
        if warning and not messagebox.askyesno("Slow scan ahead", warning + "\n\nStart the scan anyway?"):
            return

        # Reset UI
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")
        self._set_summary("Scanning...")
        for item in self.tree.get_children():
            self.tree.delete(item)
        for item in self.inv_tree.get_children():
            self.inv_tree.delete(item)
        self.inv_note_var.set("")
        self.json_text.delete("1.0", "end")
        self.last_output = None
        self.last_events = None
        self._stop_requested = False
        self._set_diff_text([("Scan in progress. When it finishes, click "
                              "\"Compare with Previous...\" and pick an older report.", "info")])
        self._enable("save", False)
        self._enable("events", False)
        self._enable("compare", False)
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.progress.config(mode="indeterminate")
        self.progress.start(40)
        self.status_var.set("Starting nmap...")

        self._show_environment()

        # XML output goes to a temp file so the GUI can stream progress on stdout
        tmp = tempfile.NamedTemporaryFile(suffix=".xml", delete=False)
        tmp.close()
        self.xml_tmp_path = tmp.name

        try:
            cmd = build_nmap_command(
                target=target,
                port_scan=True,
                service_detection=True,
                os_detection=self.os_var.get(),
                vulnerability_scan=self.vuln_var.get(),
                udp_scan=self.udp_var.get(),
                default_scripts=mode in ("full", "gentle"),
                traceroute=mode == "full",
                timing=int(self.timing_var.get()),
                custom_ports=self.ports_var.get().strip() or None,
                exclude=self.exclude_var.get().strip() or None,
                max_rate=max_rate,
                max_parallelism=max_parallelism,
                discovery_only=discovery,
                xml_output_path=self.xml_tmp_path,
                external_scripts=bool(
                    self.config.get("scan_options", {}).get("external_scripts", False)),
            )
        except (FileNotFoundError, OSError) as e:
            self._log(f"[!] {e}", "error")
            self.progress.stop()
            self.status_var.set("Scan could not start.")
            self._set_summary(f"Scan could not start: {e}")
            self._reset_buttons_after_scan()
            self._remove_xml_tmp()
            return

        # Add verbose + periodic stats so we can drive the progress bar
        cmd.extend(["-v", "--stats-every", "5s"])

        if discovery:
            self._log("[*] Discovery mode: ping sweep only — finding live hosts, "
                      "not scanning ports.", "info")
        elif gentle:
            self._log(f"[*] Gentle mode: {max_rate or GENTLE_SCAN['max_rate']} pkts/sec, "
                      "one probe at a time, no OS detection / vuln scripts / UDP.", "info")
        elif max_rate:
            self._log(f"[*] Rate limited to {max_rate} packets/sec.", "info")
        if warning:
            self._log(f"[!] {warning}", "warn")

        self._log(f"$ {format_command(cmd)}", "cmd")

        self.scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(cmd, target, "discovery" if discovery else "comprehensive"),
            daemon=True,
        )
        self.scan_thread.start()

    def _remove_xml_tmp(self) -> None:
        if self.xml_tmp_path:
            try:
                os.unlink(self.xml_tmp_path)
            except OSError:
                pass

    def _scan_worker(self, cmd: list, target: str, scan_type: str = "comprehensive") -> None:
        """Runs in a worker thread. Pushes events back via self.event_queue."""
        # Whatever goes wrong in here has to end in a "done" event. This thread
        # is the only thing that re-enables the buttons, so an exception that
        # escapes leaves the window stuck on "Scanning..." for good.
        try:
            self._run_scan(cmd, target, scan_type)
        except Exception as e:
            self.event_queue.put(("done", {"error": f"Unexpected error while scanning: {e}"}))

    def _run_scan(self, cmd: list, target: str, scan_type: str) -> None:
        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                # nmap echoes service banners and script output; decoding them
                # with the Windows locale codepage can raise mid-scan.
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=NO_WINDOW_FLAGS,
            )
        except Exception as e:
            self._remove_xml_tmp()
            self.event_queue.put(("done", {"error": f"Failed to launch nmap: {e}"}))
            return

        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self.event_queue.put(("line", line.rstrip()))
        self.proc.wait()
        rc = self.proc.returncode

        xml = ""
        if self.xml_tmp_path and os.path.exists(self.xml_tmp_path):
            try:
                with open(self.xml_tmp_path, "r", encoding="utf-8", errors="replace") as f:
                    xml = f.read()
            finally:
                self._remove_xml_tmp()

        # Stopped on purpose: nmap was killed mid-write. Whatever hosts it had
        # finished are still in the cut-off XML, so show those rather than
        # throwing an hour of scanning away.
        partial = False
        if self._stop_requested:
            salvaged = salvage_partial_xml(xml)
            if not salvaged:
                self.event_queue.put(("done", {"stopped": True}))
                return
            xml = salvaged
            partial = True

        if rc != 0 and not xml and not partial:
            hint = exit_code_hint(rc)
            self.event_queue.put(("done", {
                "error": f"nmap exited with code {rc} and produced no XML output."
                         + (f"\n\n{hint}" if hint else "")
            }))
            return

        # An aborted run still leaves parseable XML, which would otherwise be
        # reported as a successful scan that simply found nothing.
        run_error = None if partial else nmap_run_error(xml)
        if run_error:
            self.event_queue.put(("done", {
                "error": f"nmap aborted before scanning anything (exit code {rc}): {run_error}"
            }))
            return

        # Parse + analyze in the worker so the UI thread stays responsive
        self.event_queue.put(("line", "[*] Scan stopped - keeping the hosts that finished..." if partial
                              else f"[*] nmap exited with code {rc}. Parsing results..."))
        try:
            scan_result = parse_nmap_xml(xml)
        except Exception as e:
            self.event_queue.put(("done", {"error": f"Failed to parse nmap XML: {e}"}))
            return

        self.event_queue.put(("line",
                              f"[*] Parsed {scan_result.total_hosts_up} hosts up, "
                              f"{scan_result.total_hosts_down} not responding."))
        self.event_queue.put(("line", "[*] Running local rule-based analysis..."))
        analysis = analyze_locally(scan_result)
        self.event_queue.put(("line", f"[*] Local analysis complete. Overall risk: {analysis.overall_risk.upper()}"))

        output = create_insights_report(scan_result, analysis, target, __version__,
                                        scan_type=scan_type)
        events = create_nmap_chat_events(scan_result, analysis, target, __version__,
                                         scan_type=scan_type)
        if partial:
            output["scan_metadata"]["partial"] = True
        self.event_queue.put(("done", {"output": output, "events": events, "raw_xml_present": bool(xml),
                                       "partial": partial}))

    def _scan_running(self) -> bool:
        return bool(self.scan_thread and self.scan_thread.is_alive())

    def on_close(self) -> None:
        """Quit, taking a running nmap down with the window."""
        if self._scan_running():
            if not messagebox.askyesno(
                    "Scan in progress",
                    "A scan is still running. Quit and stop it?\n\n"
                    "Results from this scan will not be saved."):
                return
            # Without this nmap outlives the window and keeps probing the
            # network, for hours on a large scan, with nothing left to stop it.
            self._stop_requested = True
            if self.proc and self.proc.poll() is None:
                try:
                    self.proc.kill()
                    self.proc.wait(timeout=5)
                except Exception:
                    pass
            self._remove_xml_tmp()
        self.root.destroy()

    def stop_scan(self) -> None:
        if self.proc and self.proc.poll() is None:
            try:
                self._stop_requested = True
                self.proc.terminate()
                self._log("[!] Stop requested by user. Waiting for nmap to exit...", "warn")
                self.status_var.set("Stopping...")
            except Exception as e:
                self._log(f"[!] Failed to stop nmap: {e}", "error")

    # ---------- Queue polling (runs on the Tk main thread) ----------

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()
                if kind == "line":
                    self._handle_line(payload)
                elif kind == "done":
                    self._handle_done(payload)
                elif kind == "npcap_done":
                    self._handle_npcap_done(payload)
                elif kind == "networks":
                    self._handle_networks(payload)
                elif kind == "update_check":
                    self._handle_update_check(*payload)
                elif kind == "update_progress":
                    self._handle_update_progress(*payload)
                elif kind == "update_ready":
                    self._handle_update_ready(payload)
                elif kind == "update_error":
                    self._handle_update_error(payload)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _handle_line(self, line: str) -> None:
        tag = "info"
        if line.startswith("[!]"):
            tag = "warn"
        elif "VULNERABLE" in line.upper() or "ERROR" in line.upper():
            tag = "error"
        elif line.startswith("[+]") or "complete" in line.lower():
            tag = "ok"
        self._log(line, tag)

        m = PROGRESS_RE.search(line)
        if m:
            pct = float(m.group(1))
            if str(self.progress.cget("mode")) != "determinate":
                self.progress.stop()
                self.progress.config(mode="determinate", maximum=100)
            self.progress["value"] = pct
            self.status_var.set(f"Scanning... {pct:.1f}% (per nmap)")
            return

        if "Discovered open port" in line:
            self.status_var.set(line.strip())
        elif HOST_DISCOVERED_RE.search(line):
            self.status_var.set(line.strip())

    def _handle_done(self, payload: Dict[str, Any]) -> None:
        self.progress.stop()
        self.progress.config(mode="determinate", maximum=100, value=100)
        self._reset_buttons_after_scan()

        if payload.get("stopped"):
            self.progress.config(value=0)
            self._log("[!] Scan stopped. Nothing was saved from this run.", "warn")
            self.status_var.set("Scan stopped.")
            self._set_summary("Scan stopped before it finished - no results to show.")
            return

        if "error" in payload:
            self._log(f"[!] {payload['error']}", "error")
            self.status_var.set("Scan failed.")
            self._set_summary(f"Scan failed: {payload['error']}")
            return

        output = payload.get("output")
        if not output:
            self.status_var.set("Scan completed with no output.")
            return

        self.last_output = output
        self.last_events = payload.get("events") or []
        partial = bool(payload.get("partial"))
        if partial:
            self._log(f"[!] Scan stopped early: showing the {output.get('scan_metadata', {}).get('hosts_up', 0)} "
                      "host(s) that finished. The report is marked partial and is NOT sent to Insights.", "warn")

        # Surface scan-quality problems in the log immediately: if host
        # discovery was wrong, every result below is wrong with it.
        for obs in output.get("ai_analysis_summary", {}).get("network_observations", []):
            if obs.startswith("SCAN QUALITY"):
                self._log(f"[!] {obs}", "error")

        self._populate_results(output)
        self._populate_inventory(output)
        self.json_text.delete("1.0", "end")
        self.json_text.insert("1.0", json.dumps(output, indent=2))
        ai_summary = output.get("ai_analysis_summary", {})
        overall = ai_summary.get("overall_risk", "info").upper()
        self.status_var.set((f"Scan stopped - partial results. Risk so far: {overall}" if partial
                             else f"Scan complete. Overall risk: {overall}"))
        self._enable("save", True)
        self._enable("compare", True)
        self.nb.select(self.inv_frame)

        # Auto-write both artifacts into the output directory so a scan is never
        # lost if the user forgets to click Save: the JSON report (what Open
        # Report reloads) and the per-port NDJSON events (Insights ingestion).
        # They share one timestamped base name so a report and its events pair
        # up obviously — do NOT call generate_filename twice, its timestamp can
        # tick between calls and de-pair them.
        try:
            out_dir = self.output_dir
            target = output.get("scan_metadata", {}).get("target", "scan")
            report_path = out_dir / generate_filename(target, "json")
            written = write_json_output(output, str(report_path))
            self.last_saved_report = str(report_path)
            self._log(f"[+] Report auto-saved to {written}", "ok")
            # And the hand-over version next to it, so it exists without a click.
            try:
                html_path = report_html.write_html_report(output, str(report_path.with_suffix(".html")),
                                                          title=f"Network Scan Report - {target}")
                self._log(f"[+] HTML report auto-saved to {html_path}", "ok")
            except Exception as e:
                self._log(f"[!] Failed to write the HTML report: {e}", "warn")
        except Exception as e:
            self._log(f"[!] Failed to auto-save report: {e}", "warn")
            report_path = None
        self.refresh_history()

        if self.last_events:
            self._enable("events", True)
            try:
                # Pair the events file to the report by swapping the extension.
                if report_path is not None:
                    events_path = report_path.with_suffix(".ndjson")
                else:
                    events_path = out_dir / generate_filename(target, "ndjson")
                written = write_ndjson_events(self.last_events, str(events_path))
                self._log(f"[+] Wrote {len(self.last_events)} Insights event(s) to {written}", "ok")

                # ALSO append to the collector-watched file so Insights actually
                # ingests GUI scans. The per-scan file above is a timestamped
                # record; the Insights <localfile> tails one FIXED path, so
                # without this append a GUI scan never reaches Insights (the CLI
                # does the same via insights_events.path in main.py). Skip only
                # when it would double-write the same file we just wrote.
                insights_cfg = self.config.get("output", {}).get("insights_events", {})
                collector_path = insights_cfg.get("path")
                if partial:
                    self._log("[*] Partial scan: events saved locally only, not appended to the "
                              "Insights feed.", "warn")
                elif insights_cfg.get("enabled", True) and collector_path:
                    if Path(collector_path).resolve() != Path(events_path).resolve():
                        appended = write_ndjson_events(
                            self.last_events, collector_path, append=True)
                        self._log(f"[+] Appended {len(self.last_events)} event(s) to "
                                  f"Insights feed: {appended}", "ok")
                elif insights_cfg.get("enabled", True):
                    self._log("[*] No Insights feed path set (output.insights_events.path); "
                              "events saved locally only, not sent to Insights.", "warn")
            except Exception as e:
                self._log(f"[!] Failed to auto-write Insights events: {e}", "warn")

        self._log("[+] Scan finished. See Results and Raw JSON tabs.", "ok")

    def _reset_buttons_after_scan(self) -> None:
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    # ---------- Results rendering ----------

    def _set_summary(self, text: str) -> None:
        self.summary_box.configure(state="normal")
        self.summary_box.delete("1.0", "end")
        self.summary_box.insert("1.0", text)
        self.summary_box.configure(state="disabled")

    def _only_found_active(self, output: Dict[str, Any]) -> bool:
        """Whether the found-only view filter applies to this report."""
        return (self.only_found_var.get()
                and output.get("scan_metadata", {}).get("scan_type") != "discovery")

    def _refilter(self) -> None:
        if self.last_output:
            self._populate_results(self.last_output)
            self._populate_inventory(self.last_output)

    def _populate_results(self, output: Dict[str, Any]) -> None:
        meta = output.get("scan_metadata", {})
        ai = output.get("ai_analysis_summary", {})

        lines = [
            f"Target: {meta.get('target', 'N/A')}",
            f"Hosts up: {meta.get('hosts_up', 0)}    Hosts down: {meta.get('hosts_down', 0)}",
            f"Overall risk: {ai.get('overall_risk', 'N/A').upper()}",
            "",
            ai.get("executive_summary", ""),
        ]
        if ai.get("priority_actions"):
            lines.append("")
            lines.append("Priority actions:")
            for i, a in enumerate(ai["priority_actions"], 1):
                lines.append(f"  {i}. {a}")
        if ai.get("network_observations"):
            lines.append("")
            lines.append("Network observations:")
            for o in ai["network_observations"]:
                lines.append(f"  • {o}")
        self._set_summary("\n".join(lines))

        for item in self.tree.get_children():
            self.tree.delete(item)

        only_found = self._only_found_active(output)
        hidden = 0
        for host in output.get("hosts", []):
            # Down hosts are the absence of a reply, not a result — showing
            # them buries the live hosts. The summary keeps the down count.
            if (host.get("status") or "up") != "up":
                continue
            if only_found and not any(port_dict_is_open(p) for p in host.get("ports", [])):
                hidden += 1
                continue
            ip = host.get("ip", "?")
            hostname = host.get("hostname", "")
            ai_h = host.get("ai_analysis") or {}
            risk = (ai_h.get("risk_level") or "info").lower()
            label = ip + (f"  ({hostname})" if hostname else "")
            detail = f"Risk: {risk.upper()}"
            mac = host.get("mac_address", "")
            if mac:
                vendor = host.get("vendor", "")
                detail += f"    MAC: {mac}" + (f" ({vendor})" if vendor else "")
            host_node = self.tree.insert(
                "", "end", text=label,
                values=(detail,),
                tags=(risk,), open=True,
            )

            all_ports = host.get("ports", [])
            ports = [p for p in all_ports if port_dict_is_open(p)]
            if ports:
                pnode = self.tree.insert(host_node, "end", text=f"Open ports ({len(ports)})", values=("",))
                for p in ports:
                    label = f"{p.get('port')}/{p.get('protocol', 'tcp')} — {p.get('service', '')}"
                    detail = " ".join(x for x in (p.get("product", ""), p.get("version", "")) if x)
                    self.tree.insert(pnode, "end", text=label, values=(detail,))

            # Unanswered probes, kept visible but clearly separated from the
            # real findings — they are the absence of a reply, not a service.
            unconfirmed = [p for p in all_ports if p.get("state") == "open|filtered"]
            if unconfirmed:
                unode = self.tree.insert(
                    host_node, "end",
                    text=f"No reply — open|filtered ({len(unconfirmed)})",
                    values=("Not confirmed open; nmap got no response",))
                for p in unconfirmed:
                    self.tree.insert(
                        unode, "end",
                        text=f"{p.get('port')}/{p.get('protocol', 'tcp')} — {p.get('service', '')}",
                        values=("no response",))

            os_info = host.get("os")
            if os_info:
                self.tree.insert(host_node, "end",
                                 text=f"OS: {os_info.get('name', 'unknown')}",
                                 values=(f"{os_info.get('accuracy', 0)}% confidence",))

            findings = ai_h.get("findings", []) or []
            if findings:
                fnode = self.tree.insert(host_node, "end", text=f"Findings ({len(findings)})", values=("",))
                for f in findings:
                    sev = "info"
                    for level in ("critical", "high", "medium", "low"):
                        if level.upper() in f[:20].upper():
                            sev = level
                            break
                    self.tree.insert(fnode, "end", text=f, values=("",), tags=(sev,))

            recs = ai_h.get("recommendations", []) or []
            if recs:
                rnode = self.tree.insert(host_node, "end", text=f"Recommendations ({len(recs)})", values=("",))
                for r in recs:
                    self.tree.insert(rnode, "end", text=r, values=("",))

            vulns = host.get("vulnerabilities", []) or []
            if vulns:
                vnode = self.tree.insert(host_node, "end", text=f"nmap Vuln Findings ({len(vulns)})", values=("",))
                for v in vulns:
                    label = f"{v.get('script_id', '?')} on port {v.get('port', '?')}"
                    detail = ", ".join(v.get("cve_ids", [])) or v.get("severity", "")
                    self.tree.insert(vnode, "end", text=label, values=(detail,),
                                     tags=(v.get("severity", "info"),))

        if hidden:
            self.tree.insert(
                "", "end",
                text=f"{hidden} live host(s) with no open ports hidden",
                values=("Uncheck \"Only show hosts with open ports\" to see them",),
                tags=("info",))

    @staticmethod
    def _inventory_rows(output: Dict[str, Any], only_found: bool = False) -> list:
        """Flatten the report into one row per live host: the on-site audit view."""
        rows = []
        for host in output.get("hosts", []):
            if (host.get("status") or "up") != "up":
                continue
            # Confirmed-open only: an open|filtered port is an unanswered probe,
            # and listing it here reads as a service that is actually there.
            ports = [p for p in host.get("ports", []) if port_dict_is_open(p)]
            if only_found and not ports:
                continue
            port_bits = []
            for p in ports:
                bit = f"{p.get('port')}/{p.get('protocol', 'tcp')}"
                if p.get("service"):
                    bit += f" {p['service']}"
                port_bits.append(bit)
            os_info = host.get("os") or {}
            rows.append({
                "ip": host.get("ip", ""),
                "hostname": host.get("hostname", ""),
                "mac": host.get("mac_address", ""),
                "vendor": host.get("vendor", ""),
                "ports": ", ".join(port_bits),
                "os": os_info.get("name", ""),
            })
        return rows

    def _populate_inventory(self, output: Dict[str, Any]) -> None:
        for item in self.inv_tree.get_children():
            self.inv_tree.delete(item)

        only_found = self._only_found_active(output)
        all_rows = self._inventory_rows(output)
        rows = self._inventory_rows(output, only_found=True) if only_found else all_rows
        missing_mac = 0
        for r in rows:
            if not r["mac"]:
                missing_mac += 1
            self.inv_tree.insert("", "end", values=(
                r["ip"], r["hostname"], r["mac"], r["vendor"], r["ports"], r["os"]))

        note = f"{len(rows)} device(s) up."
        if only_found and len(rows) < len(all_rows):
            note = (f"{len(rows)} of {len(all_rows)} live device(s) shown "
                    "(hosts with no open ports hidden). CSV export includes all.")
        if output.get("scan_metadata", {}).get("scan_type") == "discovery":
            note += ("  Discovery scan — ports were not probed, so the Open Ports column is "
                     "empty by design. Re-run in Quick or Full mode to see services.")
        if missing_mac:
            note += (f"  {missing_mac} without a MAC address — MACs are only visible when "
                     "scanning the local subnet with root/administrator privileges.")
        self.inv_note_var.set(note)

    # ---------- Report loading & comparison ----------

    def _set_diff_text(self, lines: list) -> None:
        """Replace the Changes tab content with (text, tag) line pairs."""
        self.diff_text.configure(state="normal")
        self.diff_text.delete("1.0", "end")
        for text, tag in lines:
            self.diff_text.insert("end", text + "\n", tag)
        self.diff_text.configure(state="disabled")

    def open_report(self) -> None:
        """Load a previously saved report JSON into the results/inventory tabs."""
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showwarning("Scan running", "Wait for the current scan to finish first.")
            return
        initial_dir = str(self.output_dir)
        path = filedialog.askopenfilename(
            initialdir=initial_dir if Path(initial_dir).exists() else None,
            filetypes=[("Scan reports (JSON)", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        # An .ndjson is the Insights events file, not a report — reloading it
        # fails deep inside load_report with a cryptic JSON error. Catch it here
        # and point the user at the matching .json instead.
        if path.lower().endswith(".ndjson"):
            report_guess = Path(path).with_suffix(".json")
            hint = (f"\n\nTry opening {report_guess.name} instead — it's in the "
                    "same folder.") if report_guess.exists() else ""
            messagebox.showerror(
                "That's an events file, not a report",
                f"{Path(path).name} holds the per-port Insights events for that "
                "scan, not the report itself. Open the matching .json report to "
                f"reload a scan.{hint}")
            return
        self._load_report_file(path)

    def _load_report_file(self, path: str) -> None:
        try:
            output = load_report(path)
        except ValueError as e:
            messagebox.showerror("Couldn't open report", str(e))
            return

        self.last_output = output
        # A saved report doesn't carry the NDJSON events; those belong to the
        # scan that produced it, so Save Insights Events stays disabled.
        self.last_events = None
        self._enable("events", False)
        self._set_diff_text([("Report loaded. Click \"Compare with Previous...\" and pick an "
                              "older report of the same network.", "info")])

        self._populate_results(output)
        self._populate_inventory(output)
        self.json_text.delete("1.0", "end")
        self.json_text.insert("1.0", json.dumps(output, indent=2))

        meta = output.get("scan_metadata", {})
        loaded = f"{meta.get('target', '?')} scanned {meta.get('timestamp', 'at unknown time')}"
        self._log(f"[+] Loaded report: {path}", "ok")
        self._log(f"    {loaded}", "info")
        self.status_var.set(f"Loaded report: {loaded}")
        self._enable("save", True)
        self._enable("compare", True)
        self.nb.select(self.inv_frame)

    def compare_with_previous(self) -> None:
        """Diff the current results against an older saved report."""
        if not self.last_output:
            return
        initial_dir = str(self.output_dir)
        path = filedialog.askopenfilename(
            title="Pick the OLDER report to compare against",
            initialdir=initial_dir if Path(initial_dir).exists() else None,
            filetypes=[("Scan reports (JSON)", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        self._compare_with_file(path)

    def _compare_with_file(self, path: str) -> None:
        try:
            previous = load_report(path)
        except ValueError as e:
            messagebox.showerror("Couldn't open report", str(e))
            return

        comparison = diff_reports(previous, self.last_output)
        self._set_diff_text(format_diff_lines(comparison))
        self.nb.select(self.diff_frame)

        n_new = len(comparison["new_hosts"])
        n_missing = len(comparison["missing_hosts"])
        n_changed = len(comparison["changed_hosts"])
        if comparison["has_changes"]:
            self._log(f"[*] Compared with {Path(path).name}: {n_new} new host(s), "
                      f"{n_missing} missing, {n_changed} changed.", "info")
            self.status_var.set(f"Changes vs previous scan: {n_new} new, {n_missing} missing, {n_changed} changed.")
        else:
            self._log(f"[+] Compared with {Path(path).name}: no changes.", "ok")
            self.status_var.set("No changes since the previous scan.")

    # ---------- Updates ----------

    def check_for_updates(self, quiet: bool = False) -> None:
        """
        Ask GitHub for the latest release, off the UI thread.

        quiet=True is the automatic check at startup: it only speaks up when
        there is something to install, and never pops a dialog.
        """
        if self._update_in_progress:
            return
        if not quiet:
            self.status_var.set("Checking for updates...")
            self.update_btn.config(state="disabled")

        def worker() -> None:
            try:
                release, newer = updater.check_for_update(__version__)
                self.event_queue.put(("update_check", (release, newer, None, quiet)))
            except updater.UpdateError as e:
                self.event_queue.put(("update_check", (None, False, str(e), quiet)))
            except Exception as e:  # never let a check kill the thread silently
                self.event_queue.put(("update_check", (None, False, f"Update check failed: {e}", quiet)))

        threading.Thread(target=worker, daemon=True).start()

    def _handle_update_check(self, release, newer: bool, error: Optional[str], quiet: bool) -> None:
        self.update_btn.config(state="normal")
        if error:
            if quiet:
                self._log(f"[*] Update check skipped: {error}", "info")
            else:
                self.status_var.set("Update check failed.")
                self._log(f"[!] {error}", "warn")
                messagebox.showerror("Couldn't check for updates", error)
            return

        if not newer:
            if not quiet:
                self.status_var.set(f"Up to date ({__version__}).")
                self._log(f"[+] You have the latest version ({__version__}).", "ok")
                messagebox.showinfo("Up to date",
                                    f"CybX NetworkLens {__version__} is the latest version.")
            return

        self._log(f"[!] Version {release.version} is available (you have {__version__}): {release.url}", "warn")
        if quiet:
            self.status_var.set(f"Update available: version {release.version} - click \"Check for Updates...\"")
            return

        notes = release.notes.strip()
        if len(notes) > 600:
            notes = notes[:600].rstrip() + "..."
        notes_block = f"\n\nWhat's new:\n{notes}" if notes else ""

        if updater.can_self_update():
            if self._scan_running():
                messagebox.showinfo(
                    "Scan running",
                    f"Version {release.version} is available. Wait for the current scan to "
                    "finish (or stop it), then check for updates again to install it.")
                return
            if not release.has_installer:
                messagebox.showwarning(
                    "Update not downloadable",
                    f"Version {release.version} is published but has no Windows installer "
                    f"attached yet.\n\nSee {release.url}")
                return
            go = messagebox.askyesno(
                "Update available",
                f"Version {release.version} is available (you have {__version__}).{notes_block}\n\n"
                "Download and install it now?\n\nThe scanner will close while it updates and "
                "reopen on the new version. Your settings and saved reports are kept.")
            if go:
                self._start_update(release)
            return

        # Portable exe, macOS/Linux, or running from source: can't replace
        # ourselves, so hand over to the releases page.
        if messagebox.askyesno(
                "Update available",
                f"Version {release.version} is available (you have {__version__}).{notes_block}\n\n"
                "This copy can't update itself, so the download page will open in your "
                "browser. Open it now?"):
            webbrowser.open(release.url)

    def _start_update(self, release) -> None:
        self._update_in_progress = True
        self.start_btn.config(state="disabled")
        self.update_btn.config(state="disabled")
        self.progress.stop()
        self.progress.config(mode="determinate", maximum=100, value=0)
        self.status_var.set(f"Downloading version {release.version}...")
        self._log(f"[*] Downloading {release.asset_name} ({release.asset_size // (1 << 20)} MB)...", "info")

        def worker() -> None:
            try:
                dest = Path(tempfile.gettempdir()) / "CybXNetworkLens-update"
                path = updater.download_installer(
                    release, str(dest), __version__,
                    progress=lambda done, total: self.event_queue.put(("update_progress", (done, total))))
                self.event_queue.put(("update_ready", path))
            except updater.UpdateError as e:
                self.event_queue.put(("update_error", str(e)))
            except Exception as e:
                self.event_queue.put(("update_error", f"Update failed: {e}"))

        threading.Thread(target=worker, daemon=True).start()

    def _handle_update_progress(self, done: int, total: int) -> None:
        if total > 0:
            pct = 100.0 * done / total
            self.progress["value"] = pct
            self.status_var.set(f"Downloading update... {pct:.0f}%")
        else:
            self.status_var.set(f"Downloading update... {done // (1 << 20)} MB")

    def _handle_update_ready(self, installer_path: str) -> None:
        self.progress["value"] = 100
        self._log("[+] Download verified. Installing - the scanner will close and reopen "
                  "on the new version.", "ok")
        self.status_var.set("Installing update...")
        self.root.update_idletasks()
        try:
            updater.run_installer(installer_path)
        except updater.UpdateError as e:
            self._handle_update_error(str(e))
            return
        # The installer waits for this process to let go of its files, so
        # leave right away rather than making it kill us.
        self.root.after(300, self.root.destroy)

    def _handle_update_error(self, error: str) -> None:
        self._update_in_progress = False
        self.start_btn.config(state="normal")
        self.update_btn.config(state="normal")
        self.progress.config(value=0)
        self.status_var.set("Update failed.")
        self._log(f"[!] {error}", "error")
        messagebox.showerror("Update failed", error + f"\n\nYou can also download it from\n{updater.RELEASES_PAGE}")

    # ---------- Report export, settings, scheduling, history, support ----------

    def export_html_report(self) -> None:
        if not self.last_output:
            return
        target = self.last_output.get("scan_metadata", {}).get("target", "scan")
        default_name = generate_filename(target, "html")
        initial_dir = str(self.output_dir)
        Path(initial_dir).mkdir(parents=True, exist_ok=True)
        path = filedialog.asksaveasfilename(
            defaultextension=".html", initialdir=initial_dir, initialfile=default_name,
            filetypes=[("HTML report", "*.html"), ("All files", "*.*")])
        if not path:
            return
        try:
            written = report_html.write_html_report(self.last_output, path,
                                                    title=f"Network Scan Report - {target}")
            self._log(f"[+] HTML report saved to {written}", "ok")
            if messagebox.askyesno("Report exported",
                                   f"Saved {Path(written).name}.\n\nOpen it in your browser now? "
                                   "(Use the browser's Print > Save as PDF for a PDF copy.)"):
                webbrowser.open(Path(written).as_uri())
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def open_settings_dialog(self) -> None:
        cfg = self.config
        out_cfg = cfg.setdefault("output", {})
        ins_cfg = out_cfg.setdefault("insights_events", {})
        scan_cfg = cfg.setdefault("scan_options", {})
        upd_cfg = cfg.setdefault("updates", {})

        win = tk.Toplevel(self.root)
        win.title("Settings")
        win.transient(self.root)
        frame = ttk.Frame(win, padding=12)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Save reports in:").grid(row=0, column=0, sticky="w", pady=3)
        out_var = tk.StringVar(value=out_cfg.get("directory", "./output"))
        ttk.Entry(frame, textvariable=out_var, width=52).grid(row=0, column=1, sticky="we", pady=3)
        ttk.Button(frame, text="Browse...", command=lambda: (
            lambda d: out_var.set(d) if d else None)(filedialog.askdirectory(initialdir=str(self.output_dir)))
        ).grid(row=0, column=2, padx=4)
        ttk.Label(frame, text=f"Currently: {self.output_dir}", foreground=self.palette["muted"]).grid(
            row=1, column=1, sticky="w")

        ins_enabled = tk.BooleanVar(value=bool(ins_cfg.get("enabled", True)))
        ttk.Checkbutton(frame, text="Write Insights events (per-port NDJSON)", variable=ins_enabled).grid(
            row=2, column=0, columnspan=2, sticky="w", pady=(10, 3))
        ttk.Label(frame, text="Insights feed file:").grid(row=3, column=0, sticky="w", pady=3)
        ins_path = tk.StringVar(value=ins_cfg.get("path", "") or "")
        ttk.Entry(frame, textvariable=ins_path, width=52).grid(row=3, column=1, sticky="we", pady=3)
        ttk.Button(frame, text="Browse...", command=lambda: (
            lambda f: ins_path.set(f) if f else None)(filedialog.asksaveasfilename(
                title="Insights feed file the collector tails", defaultextension=".ndjson",
                initialfile="nmap_chat.ndjson"))).grid(row=3, column=2, padx=4)
        ttk.Label(frame, text="The fixed file the Insights collector tails; events are appended after every "
                              "scan. Leave empty to only keep per-scan files.", foreground=self.palette["muted"],
                  wraplength=self.px(430), justify="left").grid(row=4, column=1, sticky="w")

        ext_var = tk.BooleanVar(value=bool(scan_cfg.get("external_scripts", False)))
        ttk.Checkbutton(frame, text="Allow nmap scripts that contact third-party services (vulners CVE "
                                    "lookups - sends detected software versions to vulners.com)",
                        variable=ext_var).grid(row=5, column=0, columnspan=3, sticky="w", pady=(10, 3))
        upd_var = tk.BooleanVar(value=bool(upd_cfg.get("check_on_startup", True)))
        ttk.Checkbutton(frame, text="Check for updates when the app starts", variable=upd_var).grid(
            row=6, column=0, columnspan=3, sticky="w", pady=3)
        ui_cfg = cfg.setdefault("ui", {})
        theme_row = ttk.Frame(frame)
        theme_row.grid(row=7, column=0, columnspan=3, sticky="w", pady=(10, 3))
        ttk.Label(theme_row, text="Appearance:").pack(side="left")
        theme_var = tk.StringVar(value=ui_cfg.get("theme", "system"))
        for value, label in (("system", "Match system"), ("light", "Light"), ("dark", "Dark")):
            ttk.Radiobutton(theme_row, text=label, variable=theme_var, value=value).pack(side="left", padx=(10, 0))

        ttk.Label(frame, text=f"Saved to: {config_write_path()}", foreground=self.palette["muted"]).grid(
            row=8, column=0, columnspan=3, sticky="w", pady=(10, 0))
        btn_row = ttk.Frame(frame)
        btn_row.grid(row=9, column=0, columnspan=3, sticky="e", pady=(12, 0))

        def save() -> None:
            out_cfg["directory"] = out_var.get().strip() or "./output"
            ins_cfg["enabled"] = ins_enabled.get()
            ins_cfg["path"] = ins_path.get().strip()
            scan_cfg["external_scripts"] = ext_var.get()
            upd_cfg["check_on_startup"] = upd_var.get()
            ui_cfg["theme"] = theme_var.get()
            try:
                written = save_config(cfg)
            except OSError as e:
                messagebox.showerror("Couldn't save settings", f"{e}\n\n(Administrator rights are needed "
                                     "to write the installed settings file.)")
                return
            self.output_dir = resolve_output_dir(out_cfg["directory"])
            self._apply_theme(ui_cfg["theme"])
            self._log(f"[+] Settings saved to {written}. Reports now go to {self.output_dir}", "ok")
            self.refresh_history()
            win.destroy()

        ttk.Button(btn_row, text="Cancel", command=win.destroy).pack(side="right", padx=4)
        ttk.Button(btn_row, text="Save", command=save).pack(side="right")
        frame.columnconfigure(1, weight=1)
        win.grab_set()

    def open_schedule_dialog(self) -> None:
        current = scheduled.current_job()
        win = tk.Toplevel(self.root)
        win.title("Scheduled Scan")
        win.transient(self.root)
        frame = ttk.Frame(win, padding=12)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Run a scan automatically and record what changed since the previous one.\n"
                              "The report, an HTML copy, a _changes.txt and the Insights events are written "
                              "to the output folder each time.", wraplength=self.px(460), justify="left").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))
        status = ("Current: " + current.describe()) if current else "No scheduled scan is set up."
        ttk.Label(frame, text=status, foreground=self.palette["accent"]).grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 10))

        ttk.Label(frame, text="Target:").grid(row=2, column=0, sticky="w", pady=3)
        target_var = tk.StringVar(value=(current.target if current and current.target != "(unknown)"
                                         else self.target_var.get().strip()))
        ttk.Entry(frame, textvariable=target_var, width=36).grid(row=2, column=1, sticky="we", pady=3)
        ttk.Label(frame, text="Mode:").grid(row=3, column=0, sticky="w", pady=3)
        mode_var = tk.StringVar(value=current.mode if current else "full")
        ttk.Combobox(frame, textvariable=mode_var, values=list(scheduled.MODES), state="readonly",
                     width=10).grid(row=3, column=1, sticky="w", pady=3)
        ttk.Label(frame, text="Day:").grid(row=4, column=0, sticky="w", pady=3)
        days = ["Every day"] + scheduled.WEEKDAYS
        day_var = tk.StringVar(value=days[(current.weekday + 1) if current else 7])
        ttk.Combobox(frame, textvariable=day_var, values=days, state="readonly", width=12).grid(
            row=4, column=1, sticky="w", pady=3)
        ttk.Label(frame, text="Time (24h):").grid(row=5, column=0, sticky="w", pady=3)
        time_var = tk.StringVar(value=f"{current.hour:02d}:{current.minute:02d}" if current else "02:00")
        ttk.Entry(frame, textvariable=time_var, width=8).grid(row=5, column=1, sticky="w", pady=3)
        ttk.Label(frame, text="Runs with full rights whether or not anyone is logged in. Needs the installed "
                              "copy of NetworkLens (not the portable exe).", foreground=self.palette["muted"],
                  wraplength=self.px(460), justify="left").grid(row=6, column=0, columnspan=2, sticky="w", pady=(8, 0))

        btn_row = ttk.Frame(frame)
        btn_row.grid(row=7, column=0, columnspan=2, sticky="e", pady=(12, 0))

        def apply() -> None:
            m = re.match(r"^(\d{1,2}):(\d{2})$", time_var.get().strip())
            if not m or not (0 <= int(m.group(1)) < 24 and 0 <= int(m.group(2)) < 60):
                messagebox.showwarning("Time", "Enter the time as HH:MM, e.g. 02:00")
                return
            if not target_var.get().strip():
                messagebox.showwarning("Target", "Enter the network to scan.")
                return
            job = scheduled.ScanJob(target=target_var.get().strip(), mode=mode_var.get(),
                                    weekday=days.index(day_var.get()) - 1,
                                    hour=int(m.group(1)), minute=int(m.group(2)),
                                    output_dir=str(self.output_dir))
            ok, msg = scheduled.create(job)
            self._log(("[+] " if ok else "[!] ") + msg, "ok" if ok else "error")
            if ok:
                messagebox.showinfo("Scheduled", msg)
                win.destroy()
            else:
                messagebox.showerror("Couldn't schedule", msg)

        def remove() -> None:
            ok, msg = scheduled.remove()
            self._log(("[+] " if ok else "[!] ") + msg, "ok" if ok else "error")
            if ok:
                win.destroy()
            else:
                messagebox.showerror("Couldn't remove", msg)

        ttk.Button(btn_row, text="Close", command=win.destroy).pack(side="right", padx=4)
        ttk.Button(btn_row, text="Remove scheduled scan", command=remove,
                   state="normal" if current else "disabled").pack(side="right", padx=4)
        ttk.Button(btn_row, text="Save schedule", command=apply).pack(side="right")
        frame.columnconfigure(1, weight=1)
        win.grab_set()

    def refresh_history(self) -> None:
        """Re-list the reports in the output folder (newest first)."""
        for item in self.hist_tree.get_children():
            self.hist_tree.delete(item)
        folder = self.output_dir
        if not folder.is_dir():
            self.hist_note_var.set(f"No reports yet. They will appear here, from {folder}")
            return
        rows = []
        for p in folder.glob("scan_*.json"):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                meta = data.get("scan_metadata", {}) if isinstance(data, dict) else {}
                if "hosts" not in data:
                    continue
                risk = (data.get("ai_analysis_summary") or {}).get("overall_risk", "")
                when = self._local_time(meta.get("timestamp") or "") or (meta.get("scan_start") or "")
                kind = "discovery" if meta.get("scan_type") == "discovery" else "scan"
                if meta.get("partial"):
                    kind += " (partial)"
                rows.append((meta.get("timestamp", ""), when, meta.get("target", ""), kind,
                             meta.get("hosts_up", ""), str(risk).upper(), p))
            except (OSError, ValueError):
                continue
        rows.sort(reverse=True)
        for _ts, when, target, kind, hosts, risk, p in rows:
            self.hist_tree.insert("", "end", values=(when, target, kind, hosts, risk, p.name),
                                  tags=(risk.lower(),))
        for level in ("critical", "high", "medium", "low"):
            self.hist_tree.tag_configure(level, foreground=self.palette[level])
        self.hist_note_var.set(f"{len(rows)} report(s) in {folder}")

    @staticmethod
    def _local_time(iso_utc: str) -> str:
        """An ISO timestamp from a report, shown in local time."""
        try:
            return datetime.fromisoformat(iso_utc).astimezone().strftime("%Y-%m-%d %H:%M")
        except (ValueError, TypeError):
            return ""

    def _selected_history_path(self) -> Optional[Path]:
        sel = self.hist_tree.selection()
        if not sel:
            messagebox.showinfo("History", "Select a report in the list first.")
            return None
        return self.output_dir / self.hist_tree.item(sel[0], "values")[5]

    def open_history_item(self) -> None:
        path = self._selected_history_path()
        if path:
            self._load_report_file(str(path))

    def compare_history_item(self) -> None:
        if not self.last_output:
            messagebox.showinfo("History", "Run or open a scan first; it is compared against the selected report.")
            return
        path = self._selected_history_path()
        if path:
            self._compare_with_file(str(path))

    def export_history_item(self) -> None:
        path = self._selected_history_path()
        if not path:
            return
        try:
            report = load_report(str(path))
        except ValueError as e:
            messagebox.showerror("Couldn't open report", str(e))
            return
        out = filedialog.asksaveasfilename(defaultextension=".html", initialdir=str(self.output_dir),
                                           initialfile=path.with_suffix(".html").name,
                                           filetypes=[("HTML report", "*.html")])
        if out:
            target = report.get("scan_metadata", {}).get("target", "scan")
            written = report_html.write_html_report(report, out, title=f"Network Scan Report - {target}")
            self._log(f"[+] HTML report saved to {written}", "ok")

    def save_support_info(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Save support info", defaultextension=".zip",
            initialfile=f"networklens-support-{datetime.now().strftime('%Y%m%d_%H%M')}.zip",
            filetypes=[("Zip archive", "*.zip")])
        if not path:
            return
        try:
            written = diagnostics.write_bundle(path, self.config,
                                               extra_text={"live_log.txt": self.log.get("1.0", "end")})
            self._log(f"[+] Support info saved to {written} - send this file with your problem report.", "ok")
            messagebox.showinfo("Support info saved",
                                f"Saved {Path(written).name}.\n\nIt contains version and environment details, "
                                "the settings in use, the launch log, this window's log, and the metadata of "
                                "recent scans - no scan results.")
        except Exception as e:
            messagebox.showerror("Couldn't save", str(e))

    # ---------- File actions ----------

    def export_inventory_csv(self) -> None:
        if not self.last_output:
            return
        target = self.last_output.get("scan_metadata", {}).get("target", "scan")
        default_name = generate_filename(target, "csv")
        initial_dir = str(self.output_dir)
        Path(initial_dir).mkdir(parents=True, exist_ok=True)

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialdir=initial_dir,
            initialfile=default_name,
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            meta = self.last_output.get("scan_metadata", {})
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["IP Address", "Hostname", "MAC Address", "Vendor",
                                 "Open Ports", "OS Guess", "Scan Target", "Scan Time"])
                for r in self._inventory_rows(self.last_output):
                    writer.writerow([r["ip"], r["hostname"], r["mac"], r["vendor"],
                                     r["ports"], r["os"],
                                     meta.get("target", ""), meta.get("timestamp", "")])
            claim_for_owner(path)
            self._log(f"[+] Inventory CSV saved to {path}", "ok")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def save_report(self) -> None:
        if not self.last_output:
            return
        target = self.last_output.get("scan_metadata", {}).get("target", "scan")
        default_name = generate_filename(target)
        initial_dir = str(self.output_dir)
        Path(initial_dir).mkdir(parents=True, exist_ok=True)

        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialdir=initial_dir,
            initialfile=default_name,
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.last_output, f, indent=2)
            claim_for_owner(path)
            self._log(f"[+] Report saved to {path}", "ok")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    def save_events(self) -> None:
        if not self.last_events:
            return
        target = (self.last_output or {}).get("scan_metadata", {}).get("target", "scan")
        default_name = generate_filename(target, "ndjson")
        initial_dir = str(self.output_dir)
        Path(initial_dir).mkdir(parents=True, exist_ok=True)

        path = filedialog.asksaveasfilename(
            defaultextension=".ndjson",
            initialdir=initial_dir,
            initialfile=default_name,
            filetypes=[("NDJSON (Insights events)", "*.ndjson"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            written = write_ndjson_events(self.last_events, path)
            self._log(f"[+] Insights events saved to {written}", "ok")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    def open_output_folder(self) -> None:
        out_dir = self.output_dir
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            messagebox.showerror("Couldn't open folder", str(e))
            return
        system = platform.system()
        try:
            if system == "Darwin":
                subprocess.Popen(["open", str(out_dir)])
            elif system == "Windows":
                os.startfile(str(out_dir))  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", str(out_dir)])
        except Exception as e:
            messagebox.showerror("Couldn't open folder", str(e))


def _write_tk_diagnostics(error: Exception) -> None:
    """
    When Tk itself fails to start, say why in terms Tcl can explain.

    A TclError from tk.Tk() carries only the last message; the interpreter
    that knows the stack is already gone. Build a Tcl-only interpreter,
    record where it thinks its library is, retry loading Tk, and print
    Tcl's errorInfo. Goes to stderr, which the elevated launcher captures
    in its log file.
    """
    import _tkinter
    lines = [f"[!] Tk failed to start: {error}"]
    try:
        interp = _tkinter.create(None, "diag", "Diag", False, True, False, False, None)
        for cmd in ("info library", "info nameofexecutable", "set tcl_interactive",
                    "set auto_path", "set env(TCL_LIBRARY)", "set env(TK_LIBRARY)",
                    "set tcl_platform(user)", "pwd"):
            try:
                lines.append(f"    {cmd} -> {interp.eval(cmd)}")
            except Exception as x:
                lines.append(f"    {cmd} !! {x}")
        try:
            interp.loadtk()
            lines.append("    loadtk succeeded on a second try")
        except Exception as x:
            lines.append(f"    loadtk failed: {x}")
            try:
                lines.append("    errorInfo:\n" + interp.eval("set errorInfo"))
            except Exception as y:
                lines.append(f"    (no errorInfo: {y})")
    except Exception as x:
        lines.append(f"    diagnostic interpreter failed too: {x}")
    try:
        sys.stderr.write("\n".join(lines) + "\n")
        sys.stderr.flush()
    except Exception:
        pass


def launch() -> int:
    # macOS/Linux: offer the system password prompt and hand over to an
    # elevated copy (Windows does this through the exe's UAC manifest).
    handed_over = relaunch_elevated()
    if handed_over is not None:
        return handed_over
    if platform.system() == "Windows":
        # Per-monitor DPI awareness: otherwise Windows bitmap-stretches the
        # window on 125-200% laptop screens and everything is blurry.
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    try:
        root = tk.Tk()
    except tk.TclError as e:
        _write_tk_diagnostics(e)
        raise
    ScannerGUI(root)
    root.mainloop()
    return 0


def _run_self_test_headless() -> int:
    """
    Run the build self-test without opening a window.

    The GUI is built with --windowed, so it has no console to print to and the
    build script can only see its exit code. Results are written to a log file
    next to the executable so a failure can be read rather than guessed at.
    """
    try:
        from selftest import run_self_test
    except ImportError:
        from .selftest import run_self_test

    lines = []

    def capture(msg: str) -> None:
        lines.append(msg)
        print(msg)  # no-op when windowed, useful when built as a console app

    try:
        passed, _ = run_self_test(log=capture)
    except Exception as e:
        lines.append(f"SELF-TEST CRASHED: {e}")
        passed = False

    # Beside the executable where the build script looks for it; if that
    # folder isn't writable (an installed copy run without elevation), fall
    # back to the temp folder rather than losing the result.
    for folder in (Path(sys.executable).parent, Path(tempfile.gettempdir())):
        try:
            (folder / "selftest_gui_log.txt").write_text("\n".join(lines), encoding="utf-8")
            break
        except OSError:
            continue

    return 0 if passed else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_run_self_test_headless())
    sys.exit(launch())
