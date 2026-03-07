"""
KVAULT Theme System
-------------------
6 colour themes: dark, light, ocean, forest, rose, mono
Persisted to ~/.kvault_config
"""

import json
import os
from pathlib import Path

from src.config import CONFIG_FILENAME

# ─── Theme Definitions ───────────────────────────────────────────────────────

THEMES = {
    "dark": {
        "name": "dark",
        "primary":   "\033[38;5;39m",    # bright blue
        "secondary": "\033[38;5;244m",   # grey
        "accent":    "\033[38;5;46m",    # green
        "warning":   "\033[38;5;214m",   # orange
        "error":     "\033[38;5;196m",   # red
        "success":   "\033[38;5;46m",    # green
        "muted":     "\033[38;5;240m",   # dark grey
        "bold":      "\033[1m",
        "reset":     "\033[0m",
        "prompt":    "\033[38;5;39m",
        "logo":      "\033[38;5;39m",
        "locked":    "\033[38;5;196m",
        "unlocked":  "\033[38;5;46m",
    },
    "light": {
        "name": "light",
        "primary":   "\033[38;5;25m",
        "secondary": "\033[38;5;240m",
        "accent":    "\033[38;5;28m",
        "warning":   "\033[38;5;130m",
        "error":     "\033[38;5;124m",
        "success":   "\033[38;5;28m",
        "muted":     "\033[38;5;248m",
        "bold":      "\033[1m",
        "reset":     "\033[0m",
        "prompt":    "\033[38;5;25m",
        "logo":      "\033[38;5;25m",
        "locked":    "\033[38;5;124m",
        "unlocked":  "\033[38;5;28m",
    },
    "ocean": {
        "name": "ocean",
        "primary":   "\033[38;5;51m",    # cyan
        "secondary": "\033[38;5;67m",
        "accent":    "\033[38;5;45m",
        "warning":   "\033[38;5;220m",
        "error":     "\033[38;5;196m",
        "success":   "\033[38;5;43m",
        "muted":     "\033[38;5;60m",
        "bold":      "\033[1m",
        "reset":     "\033[0m",
        "prompt":    "\033[38;5;51m",
        "logo":      "\033[38;5;45m",
        "locked":    "\033[38;5;196m",
        "unlocked":  "\033[38;5;43m",
    },
    "forest": {
        "name": "forest",
        "primary":   "\033[38;5;34m",    # green
        "secondary": "\033[38;5;101m",
        "accent":    "\033[38;5;148m",
        "warning":   "\033[38;5;178m",
        "error":     "\033[38;5;160m",
        "success":   "\033[38;5;40m",
        "muted":     "\033[38;5;59m",
        "bold":      "\033[1m",
        "reset":     "\033[0m",
        "prompt":    "\033[38;5;34m",
        "logo":      "\033[38;5;34m",
        "locked":    "\033[38;5;160m",
        "unlocked":  "\033[38;5;40m",
    },
    "rose": {
        "name": "rose",
        "primary":   "\033[38;5;211m",   # pink
        "secondary": "\033[38;5;182m",
        "accent":    "\033[38;5;219m",
        "warning":   "\033[38;5;214m",
        "error":     "\033[38;5;196m",
        "success":   "\033[38;5;157m",
        "muted":     "\033[38;5;245m",
        "bold":      "\033[1m",
        "reset":     "\033[0m",
        "prompt":    "\033[38;5;211m",
        "logo":      "\033[38;5;211m",
        "locked":    "\033[38;5;196m",
        "unlocked":  "\033[38;5;157m",
    },
    "mono": {
        "name": "mono",
        "primary":   "\033[38;5;255m",
        "secondary": "\033[38;5;245m",
        "accent":    "\033[38;5;255m",
        "warning":   "\033[38;5;250m",
        "error":     "\033[38;5;240m",
        "success":   "\033[38;5;255m",
        "muted":     "\033[38;5;238m",
        "bold":      "\033[1m",
        "reset":     "\033[0m",
        "prompt":    "\033[38;5;255m",
        "logo":      "\033[38;5;255m",
        "locked":    "\033[38;5;240m",
        "unlocked":  "\033[38;5;255m",
    },
}

BAR_STYLES = {
    "block": ("█", "░"),
    "shade": ("▓", "░"),
    "line":  ("─", "╌"),
    "ascii": ("#", "-"),
    "dot":   ("●", "○"),
    "pipe":  ("|", " "),
}

_config_path = Path.home() / CONFIG_FILENAME
_current_theme = THEMES["dark"]
_current_bar   = "block"


def loadTheme():
    global _current_theme, _current_bar
    if _config_path.exists():
        try:
            with open(_config_path) as f:
                cfg = json.load(f)
            name = cfg.get("theme", "dark")
            bar  = cfg.get("bar", "block")
            if name in THEMES:
                _current_theme = THEMES[name]
            if bar in BAR_STYLES:
                _current_bar = bar
        except Exception:
            pass


def setTheme(name: str) -> bool:
    global _current_theme
    if name not in THEMES:
        return False
    _current_theme = THEMES[name]
    _saveConfig()
    return True


def setBar(style: str) -> bool:
    global _current_bar
    if style not in BAR_STYLES:
        return False
    _current_bar = style
    _saveConfig()
    return True


def getTheme() -> dict:
    return _current_theme


def getBar() -> tuple:
    return BAR_STYLES[_current_bar]


def _saveConfig():
    try:
        cfg = {}
        if _config_path.exists():
            with open(_config_path) as f:
                cfg = json.load(f)
        cfg["theme"] = _current_theme["name"]
        cfg["bar"]   = _current_bar
        with open(_config_path, "w") as f:
            json.dump(cfg, f)
    except Exception:
        pass
