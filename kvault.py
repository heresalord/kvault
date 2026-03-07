#!/usr/bin/env python3
"""
KVAULT — Encrypted File Vault  v3.0.0
Entry point · REPL · Command Dispatch · Auto-lock Timer
"""

import sys
import os
import signal
import threading
import shlex
import stat
import subprocess

try:
    import readline as _rl  # noqa: F401  — arrow-key history on macOS/Linux
except ImportError:
    pass

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from src import theme as theme_mod
from src import ui
from src import commands as cmd
from src.config import AUTO_LOCK_SECONDS, VERSION


# ─── Install helper ──────────────────────────────────────────────────────────

def _install_global_command():
    launcher = f"""#!/usr/bin/env bash
# KVAULT global launcher
exec python3 "{os.path.join(_HERE, 'kvault.py')}" "$@"
"""
    target = "/usr/local/bin/kvault"
    try:
        with open(target, "w") as f:
            f.write(launcher)
        os.chmod(target, os.stat(target).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        print(f"\n  ✓  Installed: {target}")
        print("     You can now type  kvault  from any terminal.\n")
    except PermissionError:
        print(f"\n  Writing to {target} requires sudo.\n")
        try:
            import tempfile
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False)
            tmp.write(launcher); tmp.close()
            os.chmod(tmp.name, 0o755)
            subprocess.run(["sudo", "cp", tmp.name, target], check=True)
            subprocess.run(["sudo", "chmod", "755", target], check=True)
            os.unlink(tmp.name)
            print(f"  ✓  Installed: {target}\n")
        except Exception as e:
            print(f"  ✗  Could not install: {e}")
            print(f'\n  Manual install:\n     echo \'{launcher.strip()}\' | sudo tee {target} && sudo chmod +x {target}\n')


# ─── Auto-lock ───────────────────────────────────────────────────────────────

_auto_lock_timer = None

def _resetAutoLock():
    global _auto_lock_timer
    if _auto_lock_timer:
        _auto_lock_timer.cancel()
    if cmd.current_vault and not cmd.current_vault.is_locked:
        _auto_lock_timer = threading.Timer(AUTO_LOCK_SECONDS, _autoLock)
        _auto_lock_timer.daemon = True
        _auto_lock_timer.start()

def _autoLock():
    if cmd.current_vault and not cmd.current_vault.is_locked:
        cmd.current_vault.lock()
        print(f"\n{ui.warn('Auto-locked after inactivity.')}")
        print(_buildPrompt(), end="", flush=True)

def _cancelAutoLock():
    global _auto_lock_timer
    if _auto_lock_timer:
        _auto_lock_timer.cancel()
        _auto_lock_timer = None


# ─── Prompt ──────────────────────────────────────────────────────────────────

def _buildPrompt() -> str:
    t = theme_mod.getTheme()
    r, p, b = t["reset"], t["prompt"], t["bold"]
    if cmd.current_vault:
        dot = (t["locked"] if cmd.current_vault.is_locked else t["unlocked"]) + "●" + r
        return f"\n  {dot} {p}{b}kvault({cmd.current_vault.name}){r} {p}›{r} "
    return f"\n  {p}{b}kvault{r} {p}›{r} "


# ─── Built-ins ───────────────────────────────────────────────────────────────

def _cmdClear(args):
    if cmd.current_vault: ui.renderVaultDashboard(cmd.current_vault)
    else:                  ui.renderDashboard(cmd.findVaultsInCwd())

def _cmdExit(args):   _gracefulExit()
def _cmdHelp(args):   ui.renderHelp()
def _cmdInstall(args): _install_global_command()


# ─── Command dispatch ─────────────────────────────────────────────────────────

DISPATCH = {
    # vault management
    "vaults":   cmd.cmdVaultsList,
    "vault":    cmd.cmdVaultsList,
    "new":      cmd.cmdVaultNew,
    "open":     cmd.cmdVaultOpen,
    "close":    cmd.cmdVaultClose,
    "lock":     cmd.cmdVaultLock,
    "unlock":   cmd.cmdVaultUnlock,
    "delete":   cmd.cmdVaultDelete,
    "passwd":   cmd.cmdVaultPasswd,
    "check":    cmd.cmdVaultCheck,
    "info":     cmd.cmdVaultInfo,
    "compact":  cmd.cmdVaultCompact,
    "upgrade":  cmd.cmdVaultUpgrade,
    # file operations
    "add":      cmd.cmdFileAdd,
    "ls":       cmd.cmdFileList,
    "get":      cmd.cmdFileGet,
    "view":     cmd.cmdFileView,
    "cat":      cmd.cmdFileView,
    "edit":     cmd.cmdFileEdit,
    "touch":    cmd.cmdFileEdit,    # alias: touch <n> creates blank file
    "rm":       cmd.cmdFileRemove,
    "rename":   cmd.cmdFileRename,
    "cp":       cmd.cmdFileCopy,
    "export":   cmd.cmdFileExport,
    # vault description
    "describe": cmd.cmdDescribe,
    "desc":     cmd.cmdDescribe,
    # phase 3
    "tags":     cmd.cmdTags,
    "search":   cmd.cmdSearch,
    "diff":     cmd.cmdDiff,
    "history":  cmd.cmdHistory,
    "compress": cmd.cmdCompress,
    # theme & general
    "theme":    cmd.cmdTheme,
    "help":     _cmdHelp,
    "clear":    _cmdClear,
    "install":  _cmdInstall,
    "exit":     _cmdExit,
    "quit":     _cmdExit,
}


def handleLine(line: str):
    _resetAutoLock()
    line = line.strip()
    if not line: return
    try:
        parts = shlex.split(line)
    except ValueError:
        parts = line.split()
    if not parts: return
    verb = parts[0].lower()
    args = parts[1:]
    if verb == "file" and args:
        verb = args[0].lower(); args = args[1:]
    handler = DISPATCH.get(verb)
    if handler:
        handler(args)
    else:
        suggestions = ui.suggestCommand(verb)
        ui.renderSuggestions(verb, suggestions)


# ─── Signal / exit ───────────────────────────────────────────────────────────

def _gracefulExit():
    _cancelAutoLock()
    if cmd.current_vault: cmd.current_vault.lock()
    print(f"\n  {ui._c('muted')}Goodbye.{ui._reset()}\n")
    sys.exit(0)

signal.signal(signal.SIGINT, lambda sig, frame: _gracefulExit())


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "install":
        _install_global_command(); return
    theme_mod.loadTheme()
    ui.renderDashboard(cmd.findVaultsInCwd())
    while True:
        try:
            line = input(_buildPrompt())
        except EOFError:
            _gracefulExit()
        except KeyboardInterrupt:
            print(); _gracefulExit()
        handleLine(line)

if __name__ == "__main__":
    main()
