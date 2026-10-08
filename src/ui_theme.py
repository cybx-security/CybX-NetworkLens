"""
Look and feel: the Sun Valley ttk theme (light/dark) plus the colours the
classic tk widgets (text boxes, tree tags) need to match it.

sv_ttk restyles every ttk widget; tk.Text and tag colours are ours to set,
so the palette here is the single place those come from. If sv_ttk is
missing (a source checkout without it) the app still runs on ttk's "clam".
"""

import platform
import subprocess
from typing import Dict

try:
    import sv_ttk
except ImportError:  # pragma: no cover - fallback only
    sv_ttk = None

THEMES = ("system", "light", "dark")

PALETTES: Dict[str, Dict[str, str]] = {
    "light": {
        "bg": "#fafafa", "card": "#ffffff", "border": "#e5e7eb",
        "fg": "#1f2937", "muted": "#6b7280", "accent": "#0f6cbd",
        "ok": "#15803d", "warn": "#b45309", "error": "#b91c1c", "cmd": "#4b5563",
        "critical": "#b91c1c", "high": "#c2410c", "medium": "#a16207", "low": "#15803d", "info": "#374151",
        "add": "#b91c1c", "remove": "#6b7280", "change": "#b45309",
        "select": "#e8f0fe",
    },
    "dark": {
        "bg": "#1c1c1c", "card": "#262626", "border": "#3a3a3a",
        "fg": "#f3f4f6", "muted": "#9ca3af", "accent": "#60a5fa",
        "ok": "#4ade80", "warn": "#fbbf24", "error": "#f87171", "cmd": "#a3a3a3",
        "critical": "#f87171", "high": "#fb923c", "medium": "#facc15", "low": "#4ade80", "info": "#d1d5db",
        "add": "#f87171", "remove": "#9ca3af", "change": "#fbbf24",
        "select": "#1e3a5f",
    },
}


def system_prefers_dark() -> bool:
    """Whether the OS is in dark mode. False when it can't be told."""
    system = platform.system()
    try:
        if system == "Darwin":
            r = subprocess.run(["defaults", "read", "-g", "AppleInterfaceStyle"],
                               capture_output=True, text=True, timeout=5)
            return r.returncode == 0 and "dark" in r.stdout.lower()
        if system == "Windows":
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as key:
                value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
                return int(value) == 0
        if system == "Linux":
            r = subprocess.run(["gsettings", "get", "org.gnome.desktop.interface", "color-scheme"],
                               capture_output=True, text=True, timeout=5)
            return "dark" in r.stdout.lower()
    except Exception:
        pass
    return False


def resolve(preference: str) -> str:
    """'system' | 'light' | 'dark' -> the concrete theme name to use."""
    if preference == "dark":
        return "dark"
    if preference == "light":
        return "light"
    return "dark" if system_prefers_dark() else "light"


def apply(root, name: str) -> Dict[str, str]:
    """Switch the ttk theme and return the matching palette."""
    name = "dark" if name == "dark" else "light"
    if sv_ttk is not None:
        try:
            sv_ttk.set_theme(name)
        except Exception:
            pass
    else:
        from tkinter import ttk
        try:
            ttk.Style(root).theme_use("clam")
        except Exception:
            pass
    palette = PALETTES[name]
    try:
        root.configure(background=palette["bg"])
    except Exception:
        pass
    return palette
