"""
KVAULT Command Handlers  —  Phase 3 complete
---------------------------------------------
Phase 3 additions:
  • cmdTags         — tag add/remove/set/list
  • cmdSearch       — full-text search with coloured results
  • cmdFileAdd      — now supports glob patterns & --compress flag
  • cmdDiff         — in-vault unified diff between two files
  • cmdHistory      — display & verify tamper-evident history log
  • cmdCompress     — change vault-level default compression setting

Threading rule (unchanged from Phase 2):
  Never run _Spinner concurrently with native C extensions (Argon2/AES-GCM).
  Use _printStep() for all crypto-touching operations.
"""

import os
import time
import getpass
import threading
import sys
import subprocess
from pathlib import Path
from typing import Optional

from src.vault import Vault, expandGlob
from src.config import (
    BRUTEFORCE_DELAYS, BRUTEFORCE_LOCKOUT_THRESHOLD, BRUTEFORCE_LOCKOUT_SECONDS,
    VAULT_SEARCH_DIRS, FOLDER_SEARCH_ROOTS, FOLDER_SEARCH_MAX_DEPTH,
    CLIPBOARD_COPY, CLIPBOARD_CLEAR_SECONDS,
)
from src import ui


# ─── Global state ────────────────────────────────────────────────────────────

current_vault: Optional[Vault] = None
_vault_list_cache: list        = []
_failed_attempts: int          = 0
_lockout_until: float          = 0.0
_open_vaults: dict             = {}


# ─── Auth helpers ────────────────────────────────────────────────────────────

def promptPassword(prompt: str = "Password: ") -> str:
    try:
        return getpass.getpass(f"  {ui._c('secondary')}{prompt}{ui._reset()}")
    except (EOFError, KeyboardInterrupt):
        print(); return ""


def _checkBruteforce() -> bool:
    now = time.time()
    if now < _lockout_until:
        print(ui.error(f"Too many failed attempts. Locked out for {int(_lockout_until - now)}s."))
        return False
    return True


def _recordFailure():
    global _failed_attempts, _lockout_until
    _failed_attempts += 1
    delay = BRUTEFORCE_DELAYS.get(_failed_attempts, 0)
    if _failed_attempts >= BRUTEFORCE_LOCKOUT_THRESHOLD:
        _lockout_until = time.time() + BRUTEFORCE_LOCKOUT_SECONDS
        print(ui.warn(f"10 failed attempts. Locked out for {BRUTEFORCE_LOCKOUT_SECONDS}s."))
    elif delay:
        print(ui.warn(f"Wrong password. Waiting {delay}s…"))
        time.sleep(delay)
    else:
        print(ui.error("Wrong password."))


def _resetFailures():
    global _failed_attempts, _lockout_until
    _failed_attempts = 0; _lockout_until = 0.0


def _requireOpen() -> bool:
    if current_vault is None:
        print(ui.warn("No vault is open.  Use  open <name|path>  to open one.")); return False
    if current_vault.is_locked:
        print(ui.warn("Vault is locked.  Use  unlock  to re-enter the password.")); return False
    return True


# ─── Spinner (safe for pure-Python ops only) ─────────────────────────────────

class _Spinner:
    FRAMES = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

    def __init__(self, msg: str):
        self._msg = msg; self._running = False; self._t = None; self._i = 0

    def start(self):
        self._running = True
        self._t = threading.Thread(target=self._spin, daemon=True)
        self._t.start()

    def _spin(self):
        c, r = ui._c("accent"), ui._reset()
        while self._running:
            sys.stdout.write(f"\r  {c}{self.FRAMES[self._i % 10]}{r}  {self._msg} ")
            sys.stdout.flush(); self._i += 1; time.sleep(0.08)

    def stop(self, final: str = None):
        self._running = False
        if self._t: self._t.join()
        sys.stdout.write("\r" + " " * (len(self._msg) + 16) + "\r")
        sys.stdout.flush()
        if final: print(final)


def _printStep(msg: str):
    """Status line safe to use alongside native C calls (no thread)."""
    print(f"  {ui._c('secondary')}·{ui._reset()}  {msg}", flush=True)


# ─── Folder search ───────────────────────────────────────────────────────────

def _findFoldersByName(name: str) -> list:
    home = Path.home(); name_l = name.lower(); matches = []; seen = set()
    roots = [Path.cwd(), Path.cwd().parent] + [
        (home / r) if r else home for r in FOLDER_SEARCH_ROOTS
    ]
    SKIP = {"node_modules","__pycache__",".git","Library","System",
            "private","usr","bin","sbin","etc","var","tmp","Applications"}

    def _walk(p: Path, depth: int):
        if depth > FOLDER_SEARCH_MAX_DEPTH: return
        try:
            for child in p.iterdir():
                if not child.is_dir() or child.name.startswith(".") or child.name in SKIP:
                    continue
                key = str(child.resolve())
                if key not in seen:
                    seen.add(key)
                    if name_l in child.name.lower(): matches.append(child)
                    _walk(child, depth + 1)
        except PermissionError: pass

    for root in roots:
        if not root.exists(): continue
        key = str(root.resolve())
        if key not in seen:
            seen.add(key)
            if name_l in root.name.lower(): matches.append(root)
            _walk(root, 1)
    matches.sort(key=lambda p: (len(p.parts), str(p).lower()))
    return matches


def _resolveFolderArg(folder_name: str) -> Optional[Path]:
    spin = _Spinner(f"Searching for '{folder_name}'…")
    spin.start(); matches = _findFoldersByName(folder_name); spin.stop()
    if not matches:
        print(ui.error(f"No folder found matching '{folder_name}'."))
        print(ui.info_msg("Tip: use  --to \"/full/path\"  for an exact path.")); return None
    if len(matches) == 1:
        print(ui.info_msg(f"Found: {matches[0]}")); return matches[0]
    print(ui.info_msg(f"Found {len(matches)} folders matching '{folder_name}':\n"))
    for i, m in enumerate(matches, 1):
        print(f"  {ui._c('primary')}{i}.{ui._reset()}  {m}")
    print()
    try:
        raw = input(f"  {ui._c('secondary')}Choose a number (Enter to cancel): {ui._reset()}")
    except (EOFError, KeyboardInterrupt):
        print(); return None
    raw = raw.strip()
    if not raw: print(ui.info_msg("Cancelled.")); return None
    if raw.isdigit():
        idx = int(raw) - 1
        if 0 <= idx < len(matches): return matches[idx]
    print(ui.error("Invalid selection.")); return None


# ─── Clipboard ───────────────────────────────────────────────────────────────

def _copyToClipboard(text: str):
    try:
        if sys.platform == "darwin":
            subprocess.run(["pbcopy"], input=text.encode(), check=True, capture_output=True)
        elif sys.platform.startswith("linux"):
            subprocess.run(["xclip","-selection","clipboard"],
                           input=text.encode(), check=True, capture_output=True)
        elif sys.platform == "win32":
            subprocess.run(["clip"], input=text.encode(), check=True, capture_output=True)
    except Exception: pass


def _scheduleClear(delay: int):
    if delay <= 0: return
    def _clear():
        time.sleep(delay)
        try:
            if sys.platform == "darwin":
                subprocess.run(["pbcopy"], input=b"", check=True, capture_output=True)
            elif sys.platform.startswith("linux"):
                subprocess.run(["xclip","-selection","clipboard"],
                               input=b"", check=True, capture_output=True)
            elif sys.platform == "win32":
                subprocess.run(["clip"], input=b"", check=True, capture_output=True)
        except Exception: pass
    threading.Thread(target=_clear, daemon=True).start()


# ─── Vault discovery ─────────────────────────────────────────────────────────

def findVaultsOnMachine(extra_path: str = None) -> list:
    home = Path.home()
    dirs = [Path.cwd()] + [home / d for d in VAULT_SEARCH_DIRS[1:] if (home/d).exists()] + [home]
    if extra_path:
        ep = Path(extra_path).expanduser()
        if ep.exists(): dirs.append(ep)
    found = []; seen = set()
    for d in dirs:
        try:
            for f in sorted(d.glob("*.kvt")):
                k = str(f.resolve())
                if k not in seen: seen.add(k); found.append(str(f))
        except PermissionError: pass
    return found


def findVaultsInCwd() -> list:
    return [p.stem for p in sorted(Path.cwd().glob("*.kvt"))]


def _resolveVaultPath(query: str) -> Optional[Path]:
    global _vault_list_cache
    if query.isdigit() and _vault_list_cache:
        idx = int(query) - 1
        if 0 <= idx < len(_vault_list_cache):
            p = Path(_vault_list_cache[idx])
            if p.exists(): return p
    expanded = Path(query).expanduser()
    if expanded.is_absolute() or query.startswith("~"):
        if expanded.exists(): return expanded
        w = expanded.with_suffix(".kvt")
        if w.exists(): return w
    stem = query[:-4] if query.lower().endswith(".kvt") else query
    c = Path.cwd() / f"{stem}.kvt"
    if c.exists(): return c
    if not _vault_list_cache: _vault_list_cache = findVaultsOnMachine()
    for cached in _vault_list_cache:
        cp = Path(cached)
        if cp.stem.lower() == stem.lower() and cp.exists(): return cp
    return None


# ─── Vault commands ──────────────────────────────────────────────────────────

def cmdVaultsList(args: list):
    global _vault_list_cache
    spin = _Spinner("Scanning for vaults…"); spin.start()
    vaults = findVaultsOnMachine(args[0] if args else None); spin.stop()
    _vault_list_cache = vaults; ui.renderVaultList(vaults)


def cmdVaultNew(args: list):
    global current_vault
    if not args:
        print(ui.error("Usage: new <n>  [--memory <MB>]  [--time <N>]  [--recovery]")); return
    name = None; memory_mb = 64; time_cost = 3; ask_recovery = False
    i = 0
    while i < len(args):
        if args[i] == "--memory" and i+1 < len(args):
            try: memory_mb = int(args[i+1]); i += 2
            except ValueError: print(ui.error("--memory requires int MB.")); return
        elif args[i] == "--time" and i+1 < len(args):
            try: time_cost = int(args[i+1]); i += 2
            except ValueError: print(ui.error("--time requires int.")); return
        elif args[i] == "--recovery": ask_recovery = True; i += 1
        else: name = args[i]; i += 1
    if not name: print(ui.error("Provide a vault name.")); return
    path = Path.cwd() / f"{name}.kvt"
    if path.exists(): print(ui.error(f"Vault already exists: {path}")); return
    pw1 = promptPassword("Master password: ")
    if not pw1: return
    if len(pw1) < 8: print(ui.warn("Short password (< 8 chars)."))
    pw2 = promptPassword("Confirm password: ")
    if pw1 != pw2: print(ui.error("Passwords do not match.")); return
    recovery = promptPassword("Recovery phrase (Enter to skip): ") if ask_recovery else ""
    _printStep(f"Deriving key (Argon2id {memory_mb}MB t={time_cost})…")
    try:
        v = Vault.create(path, pw1,
                         argon2_override={"memory_cost": memory_mb*1024, "time_cost": time_cost},
                         recovery_phrase=recovery)
        current_vault = v; _open_vaults[v.name] = v
        print(ui.success(f"Vault '{name}' created and opened."))
        if recovery: print(ui.info_msg("Recovery phrase stored as HMAC."))
    except Exception as e: print(ui.error(f"Failed: {e}"))


def cmdVaultOpen(args: list):
    global current_vault
    if not args:
        print(ui.error("Usage: open <name|#|path>  |  open --tofolder <n>")); return
    path = None
    if args[0] == "--tofolder" and len(args) > 1:
        folder = _resolveFolderArg(args[1])
        if folder is None: return
        kvaults = list(folder.glob("*.kvt"))
        if not kvaults: print(ui.error(f"No .kvt files in: {folder}")); return
        if len(kvaults) == 1:
            path = kvaults[0]; print(ui.info_msg(f"Found: {path}"))
        else:
            print(ui.info_msg(f"Found {len(kvaults)} vault(s):\n"))
            for i, k in enumerate(kvaults, 1):
                print(f"  {ui._c('primary')}{i}.{ui._reset()}  {k.stem}")
            try:
                r = input(f"\n  {ui._c('secondary')}Choose (Enter to cancel): {ui._reset()}").strip()
            except (EOFError, KeyboardInterrupt): print(); return
            if not r or not r.isdigit(): print(ui.info_msg("Cancelled.")); return
            idx = int(r) - 1
            if 0 <= idx < len(kvaults): path = kvaults[idx]
            else: print(ui.error("Invalid.")); return
    else:
        path = _resolveVaultPath(" ".join(args))
    if path is None or not path.exists():
        print(ui.error(f"Vault not found: {' '.join(args)}"))
        nb = findVaultsInCwd()
        if nb:
            print(ui.info_msg("Vaults in this directory:"))
            for i, n in enumerate(nb, 1): print(f"       {i}.  {n}")
        print(ui.info_msg("Use  vaults  to search the whole machine.")); return
    if not _checkBruteforce(): return
    pw = promptPassword("Password: ")
    if not pw: return
    _printStep("Deriving key (Argon2id)…")
    try:
        v = Vault.open(path, pw)
        _resetFailures(); current_vault = v; _open_vaults[v.name] = v
        print(ui.success(f"Vault '{v.name}' opened.  ({path})"))
    except ValueError as e:
        msg = str(e); _recordFailure()
        if "FROZEN" in msg:
            print(ui.error("Vault is FROZEN after too many failed attempts."))
            rec = promptPassword("Recovery phrase: ")
            _attemptFrozenUnlock(path, pw, rec)
        else: print(ui.error(msg))


def _attemptFrozenUnlock(path: Path, pw: str, rec: str):
    global current_vault
    _printStep("Verifying recovery phrase…")
    try:
        v = Vault.open(path, pw, recovery_phrase=rec)
        _resetFailures(); current_vault = v; _open_vaults[v.name] = v
        print(ui.success(f"Vault '{v.name}' unlocked via recovery phrase."))
    except ValueError as e: print(ui.error(str(e)))


def cmdVaultClose(args: list):
    global current_vault
    if current_vault is None: print(ui.warn("No vault is open.")); return
    name = current_vault.name; _open_vaults.pop(name, None)
    current_vault.lock(); current_vault = None
    print(ui.success(f"Vault '{name}' closed."))


def cmdVaultLock(args: list):
    if current_vault is None: print(ui.warn("No vault is open.")); return
    current_vault.lock(); print(ui.success("Vault locked. Keys wiped (3-pass)."))


def cmdVaultUnlock(args: list):
    if current_vault is None: print(ui.warn("No vault is open.")); return
    if not current_vault.is_locked: print(ui.info_msg("Already unlocked.")); return
    if not _checkBruteforce(): return
    pw = promptPassword("Password: ")
    if not pw: return
    _printStep("Deriving key (Argon2id)…")
    try:
        current_vault.unlock(pw); _resetFailures()
        print(ui.success("Vault unlocked."))
    except ValueError as e: _recordFailure(); print(ui.error(str(e)))


def cmdVaultDelete(args: list):
    global current_vault
    if current_vault is None: print(ui.warn("No vault is open.")); return
    print(ui.warn(f"Permanently destroy '{current_vault.name}'? This cannot be undone."))
    c = promptPassword("Confirm master password: ")
    if not c: print(ui.info_msg("Cancelled.")); return
    try: Vault.open(current_vault.path, c).lock()
    except Exception: print(ui.error("Wrong password. Cancelled.")); return
    path = current_vault.path; name = current_vault.name
    _open_vaults.pop(name, None); current_vault.lock(); current_vault = None
    try:
        size = path.stat().st_size
        # 3-pass wipe matching the in-memory key wipe (0x00 → 0xFF → 0x00)
        with open(path, "r+b") as f:
            for val in (b"\x00", b"\xff", b"\x00"):
                f.seek(0); f.write(val * size); f.flush(); os.fsync(f.fileno())
        path.unlink()
        print(ui.success(f"Vault '{name}' permanently destroyed."))
    except Exception as e: print(ui.error(f"Error: {e}"))


def cmdVaultPasswd(args: list):
    if not _requireOpen(): return
    pw = promptPassword("New password: ")
    if not pw: return
    if len(pw) < 8: print(ui.warn("Short password (< 8 chars)."))
    if promptPassword("Confirm: ") != pw: print(ui.error("Passwords do not match.")); return
    _printStep("Re-encrypting vault…")
    try: current_vault.changePassword(pw); print(ui.success("Password changed."))
    except Exception as e: print(ui.error(f"Failed: {e}"))


def cmdVaultCheck(args: list):
    if not _requireOpen(): return
    _printStep("Verifying all blobs…")
    bad = current_vault.check()
    if not bad: print(ui.success(f"All {len(current_vault._index)} files verified — vault intact."))
    else:
        print(ui.error(f"Corrupted / tampered ({len(bad)}):"))
        for n in bad: print(f"    {ui._c('error')}·{ui._reset()} {n}")


def cmdVaultInfo(args: list):
    if current_vault is None: print(ui.warn("No vault is open.")); return
    d = current_vault.info()
    desc = d.get("description", "").strip()
    print()
    if desc:
        print(f"  {ui._c('secondary')}{'Description':<22}{ui._reset()}{desc}")
    rows = [
        ("Vault",             d["name"]),
        ("Location",          str(current_vault.path)),
        ("Format",            f"v{d['version']}"),
        ("Files",             str(d["file_count"])),
        ("Data size",         ui._fmt_size(d["total_size"])),
        ("Vault size",        ui._fmt_size(d["vault_size"])),
        ("Modified",          d["modified"]),
        ("Argon2id mem",      d.get("argon2_mem","64 MB")),
        ("Argon2id t/p",      f"{d.get('argon2_time',3)} / {d.get('argon2_threads',4)}"),
        ("Compression",       d.get("compression","none")),
        ("Compressed files",  str(d.get("compressed_files",0))),
        ("Tags (unique)",     str(d.get("tag_count",0))),
        ("History entries",   str(d.get("history_entries",0))),
        ("Recovery phrase",   ui._c("success")+"set"+ui._reset() if d.get("has_recovery")
                              else ui._c("muted")+"not set"+ui._reset()),
        ("Failed attempts",   str(d.get("failed_attempts",0))),
        ("Frozen",            ui._c("error")+"YES"+ui._reset() if d.get("frozen")
                              else ui._c("muted")+"no"+ui._reset()),
    ]
    for k, v in rows: print(f"  {ui._c('secondary')}{k:<22}{ui._reset()}{v}")
    print()


def cmdVaultCompact(args: list):
    if not _requireOpen(): return
    _printStep("Compacting vault…"); current_vault.compact()
    print(ui.success("Vault compacted."))


def cmdVaultUpgrade(args: list):
    print(ui.warn("To upgrade: open with 'open', then run 'passwd' to re-key."))


# ─── File commands ────────────────────────────────────────────────────────────

def cmdFileAdd(args: list):
    """
    add <path|glob> [path2…]    encrypt & store (glob supported)
    add --recursive <dir>       recursively add all files in directory
    add --compress <algo>       zstd | zlib | none  (overrides vault default)
    add --tag <tag1,tag2>       attach tags immediately
    """
    if not _requireOpen(): return
    if not args:
        print(ui.error(
            "Usage: add <path|glob> [path2…]\n"
            "       add --recursive <dir>\n"
            "       add --compress zstd|zlib|none\n"
            "       add --tag tag1,tag2"
        )); return

    recursive = False; compression = None; tags = []
    raw_args = []
    i = 0
    while i < len(args):
        if args[i] in ("--recursive", "-r"): recursive = True; i += 1
        elif args[i] == "--compress" and i+1 < len(args):
            compression = args[i+1].lower(); i += 2
        elif args[i] == "--tag" and i+1 < len(args):
            tags = [t.strip() for t in args[i+1].split(",") if t.strip()]; i += 2
        else: raw_args.append(args[i]); i += 1

    # Expand globs and plain paths
    files_to_add = []
    for a in raw_args:
        p = Path(a).expanduser()
        # Try glob expansion first
        globbed = expandGlob(a)
        if globbed:
            files_to_add.extend(globbed)
        elif p.exists():
            if p.is_dir():
                files_to_add.extend(
                    f for f in (p.rglob("*") if recursive else p.iterdir())
                    if f.is_file()
                )
            else:
                files_to_add.append(p)
        else:
            print(ui.warn(f"Path not found: {a}"))

    if not files_to_add: print(ui.warn("No files found to add.")); return

    total = len(files_to_add)
    for i, fp in enumerate(files_to_add, 1):
        tag_str = f"  [{','.join(tags)}]" if tags else ""
        _printStep(f"Encrypting  {fp.name}  ({i}/{total}){tag_str}…")
        try:
            entry = current_vault.addFile(fp, tags=tags, compression=compression)
            comp_note = f"  [{entry['compression']}]" if entry["compression"] != "none" else ""
            print(ui.success(
                f"Added  {entry['name']}  ({ui._fmt_size(entry['size'])}){comp_note}"
            ))
        except Exception as e: print(ui.error(f"Failed to add {fp.name}: {e}"))


def cmdFileList(args: list):
    if not _requireOpen(): return
    ui.renderFileList(current_vault)


def _parseGetDest(args: list):
    dest = None; parts = []; i = 0
    while i < len(args):
        if args[i] == "--to" and i+1 < len(args):
            dest = Path(args[i+1]).expanduser(); i += 2
        elif args[i] == "--tofolder" and i+1 < len(args):
            dest = _resolveFolderArg(args[i+1])
            if dest is None: return None, None
            i += 2
        else: parts.append(args[i]); i += 1
    return parts, dest


def cmdFileGet(args: list):
    if not _requireOpen(): return
    if not args:
        print(ui.error(
            "Usage: get <# or name>  [--to <path>]\n"
            "       get <# or name>  [--tofolder <folder>]"
        )); return
    parts, dest = _parseGetDest(args)
    if parts is None: return
    if dest is None: dest = Path.cwd()
    query = " ".join(parts)
    if not query: print(ui.error("Specify a file number or name.")); return
    entry = current_vault.findEntry(query)
    if entry is None:
        print(ui.error(f"File not found: {query}")); _suggestFiles(query); return
    _printStep(f"Decrypting  {entry['name']}  ({ui._fmt_size(entry.get('size',0))})…")
    try:
        out = current_vault.extractFile(entry, dest)
        print(ui.success(f"Extracted  '{entry['name']}'  →  {out}"))
    except Exception as e: print(ui.error(f"Failed: {e}"))


def cmdFileView(args: list):
    """
    view <# or name>          preview a text file in the terminal
    view <# or name> --clip   also copy to clipboard (auto-clears after CLIPBOARD_CLEAR_SECONDS)
    """
    if not _requireOpen(): return
    if not args: print(ui.error("Usage: view <# or name>  [--clip]")); return
    clip = "--clip" in args
    args = [a for a in args if a != "--clip"]
    entry = current_vault.findEntry(" ".join(args))
    if entry is None:
        print(ui.error(f"File not found: {args[0]}")); _suggestFiles(args[0]); return
    _printStep(f"Decrypting {entry['name']}…")
    try:
        text = current_vault.viewFile(entry)
        print(f"\n{ui._c('muted')}" + "─"*62 + ui._reset())
        print(text)
        print(f"{ui._c('muted')}" + "─"*62 + ui._reset() + "\n")
        # Clipboard is opt-in: requires --clip flag OR CLIPBOARD_COPY = True in config
        if clip or CLIPBOARD_COPY:
            _copyToClipboard(text)
            _scheduleClear(CLIPBOARD_CLEAR_SECONDS)
            print(ui.info_msg(f"Copied to clipboard — auto-clears in {CLIPBOARD_CLEAR_SECONDS}s."))
    except ValueError as e: print(ui.warn(str(e)))
    except Exception as e: print(ui.error(f"Failed: {e}"))


def cmdFileRemove(args: list):
    if not _requireOpen(): return
    if not args: print(ui.error("Usage: rm <# or name>")); return
    entry = current_vault.findEntry(" ".join(args))
    if entry is None: print(ui.error(f"File not found: {args[0]}")); return
    _printStep(f"Removing '{entry['name']}'…")
    try: current_vault.removeFile(entry); print(ui.success(f"Removed '{entry['name']}'."))
    except Exception as e: print(ui.error(f"Failed: {e}"))


def cmdFileRename(args: list):
    if not _requireOpen(): return
    if len(args) < 2: print(ui.error("Usage: rename <# or name> <new-name>")); return
    entry = current_vault.findEntry(args[0])
    if entry is None: print(ui.error(f"File not found: {args[0]}")); return
    old = entry["name"]; current_vault.renameFile(entry, args[1])
    print(ui.success(f"Renamed '{old}'  →  '{args[1]}'."))


def cmdFileCopy(args: list):
    if not _requireOpen(): return
    if len(args) < 2: print(ui.error("Usage: cp <# or name> <TargetVault>")); return
    entry = current_vault.findEntry(args[0])
    if entry is None: print(ui.error(f"File not found: {args[0]}")); return
    tp = _resolveVaultPath(args[1])
    if tp is None: print(ui.error(f"Target vault not found: {args[1]}")); return
    pw = promptPassword(f"Password for '{args[1]}': ")
    if not pw: return
    _printStep(f"Opening '{args[1]}'…")
    try: tv = Vault.open(tp, pw)
    except ValueError as e: print(ui.error(str(e))); return
    _printStep(f"Copying '{entry['name']}'…")
    try:
        current_vault.copyFileTo(entry, tv); tv.lock()
        print(ui.success(f"Copied '{entry['name']}' into vault '{args[1]}'."))
    except Exception as e: tv.lock(); print(ui.error(f"Failed: {e}"))


def cmdFileExport(args: list):
    if not _requireOpen(): return
    if not args:
        print(ui.error("Usage: export <dest-dir>  |  export --tofolder <n>")); return
    if args[0] == "--tofolder" and len(args) > 1:
        dest = _resolveFolderArg(args[1])
        if dest is None: return
    else:
        dest = Path(args[0]).expanduser()
    print(ui.warn("About to decrypt ALL files. Confirm password to proceed."))
    c = promptPassword("Confirm master password: ")
    if not c: print(ui.info_msg("Export cancelled.")); return
    try: Vault.open(current_vault.path, c).lock()
    except Exception: print(ui.error("Wrong password. Export cancelled.")); return
    count = len(current_vault._index)
    _printStep(f"Exporting {count} file{'s' if count!=1 else ''}…")
    try:
        current_vault.exportAll(dest)
        print(ui.success(f"Exported {count} file{'s' if count!=1 else ''} to {dest}"))
    except Exception as e: print(ui.error(f"Failed: {e}"))


# ─── Phase 3: Tags ───────────────────────────────────────────────────────────

def cmdTags(args: list):
    """
    tags list                       list all tags → files mapping
    tags list <# or name>           list tags on a specific file
    tags add  <# or name> <t1,t2>   add tags to a file
    tags rm   <# or name> <t1,t2>   remove tags from a file
    tags set  <# or name> <t1,t2>   replace all tags on a file
    tags search <tag>               alias for: search <tag>
    """
    if not _requireOpen(): return
    if not args or args[0] == "list":
        if len(args) > 1:
            # List tags on a specific file
            entry = current_vault.findEntry(args[1])
            if entry is None: print(ui.error(f"File not found: {args[1]}")); return
            tags = entry.get("tags", [])
            if tags:
                print(f"\n  {ui._c('primary')}{entry['name']}{ui._reset()}")
                for t in tags:
                    print(f"    {ui._c('accent')}#{t}{ui._reset()}")
                print()
            else:
                print(ui.info_msg(f"'{entry['name']}' has no tags."))
        else:
            # List all tags
            mapping = current_vault.listAllTags()
            if not mapping: print(ui.info_msg("No tags in this vault.")); return
            print()
            for tag, files in mapping.items():
                print(f"  {ui._c('accent')}#{tag}{ui._reset()}")
                for f in files:
                    print(f"    {ui._c('muted')}· {f}{ui._reset()}")
            print()
        return

    sub = args[0]
    if sub in ("add", "rm", "remove", "set"):
        if len(args) < 3:
            print(ui.error(f"Usage: tags {sub} <# or name> <tag1,tag2>")); return
        entry = current_vault.findEntry(args[1])
        if entry is None: print(ui.error(f"File not found: {args[1]}")); return
        tag_list = [t.strip() for t in args[2].split(",") if t.strip()]
        try:
            if sub == "add":
                result = current_vault.addTags(entry, tag_list)
                print(ui.success(f"Tags on '{entry['name']}': " + ", ".join(f"#{t}" for t in result)))
            elif sub in ("rm", "remove"):
                result = current_vault.removeTags(entry, tag_list)
                print(ui.success(f"Removed. Tags on '{entry['name']}': " +
                                 (", ".join(f"#{t}" for t in result) or "(none)")))
            elif sub == "set":
                result = current_vault.setTags(entry, tag_list)
                print(ui.success(f"Tags on '{entry['name']}': " + ", ".join(f"#{t}" for t in result)))
        except Exception as e: print(ui.error(str(e)))
    elif sub == "search":
        if len(args) < 2: print(ui.error("Usage: tags search <tag>")); return
        cmdSearch(args[1:])
    else:
        print(ui.error(f"Unknown tags subcommand: {sub}  (list · add · rm · set · search)"))


# ─── Phase 3: Search ─────────────────────────────────────────────────────────

def cmdSearch(args: list):
    """
    search <query>    search names, tags, MIME, date
    Supports multiple terms (AND logic): search pdf 2026 important
    """
    if not _requireOpen(): return
    if not args: print(ui.error("Usage: search <query terms…>")); return
    query = " ".join(args)
    results = current_vault.search(query)
    if not results:
        print(ui.info_msg(f"No files matched: '{query}'")); return
    print(f"\n  {ui._c('secondary')}Found {len(results)} file{'s' if len(results)!=1 else ''}:{ui._reset()}\n")
    for e in results:
        tags = "  " + "  ".join(f"{ui._c('accent')}#{t}{ui._reset()}" for t in e.get("tags",[]))
        idx  = current_vault._index.index(e) + 1
        print(
            f"  {ui._c('primary')}{idx:<4}{ui._reset()}"
            f"{ui._c('bold')}{e['name']:<30}{ui._reset()}"
            f"  {ui._c('muted')}{ui._fmt_size(e.get('size',0)):>9}  "
            f"{e.get('mime','BIN'):<5}{ui._reset()}"
            f"{tags}"
        )
    print()


# ─── Phase 3: Diff ───────────────────────────────────────────────────────────

def cmdDiff(args: list):
    """
    diff <#|name> <#|name>    unified diff between two text files in the vault
    """
    if not _requireOpen(): return
    if len(args) < 2:
        print(ui.error("Usage: diff <#|name> <#|name>")); return
    a = current_vault.findEntry(args[0])
    b = current_vault.findEntry(args[1])
    if a is None: print(ui.error(f"File not found: {args[0]}")); return
    if b is None: print(ui.error(f"File not found: {args[1]}")); return
    if a["id"] == b["id"]:
        print(ui.info_msg("Both arguments refer to the same file.")); return
    _printStep(f"Decrypting {a['name']} and {b['name']}…")
    try:
        diff = current_vault.diffFiles(a, b)
        print(f"\n{ui._c('muted')}" + "─"*62 + ui._reset())
        if diff == "(files are identical)":
            print(ui.info_msg("Files are identical."))
        else:
            for line in diff.splitlines():
                if line.startswith("+++") or line.startswith("---"):
                    print(ui._c("secondary") + line + ui._reset())
                elif line.startswith("+"):
                    print(ui._c("success") + line + ui._reset())
                elif line.startswith("-"):
                    print(ui._c("error") + line + ui._reset())
                elif line.startswith("@@"):
                    print(ui._c("accent") + line + ui._reset())
                else:
                    print(ui._c("muted") + line + ui._reset())
        print(f"{ui._c('muted')}" + "─"*62 + ui._reset() + "\n")
    except ValueError as e: print(ui.warn(str(e)))
    except Exception as e: print(ui.error(f"Failed: {e}"))


# ─── Phase 3: History ────────────────────────────────────────────────────────

def cmdHistory(args: list):
    """
    history [N]       show last N operations (default 20)
    history verify    verify the HMAC chain
    """
    if not _requireOpen(): return

    if args and args[0] == "verify":
        _printStep("Verifying history chain…")
        ok, broken = current_vault.verifyHistory()
        if ok:
            total = len(current_vault._history)
            print(ui.success(f"History chain intact — {total} entries verified."))
        else:
            print(ui.error(f"History chain BROKEN at entry #{broken+1}. Possible tampering."))
        return

    limit = 20
    if args:
        try: limit = int(args[0])
        except ValueError: pass

    entries = current_vault.getHistory(limit)
    if not entries: print(ui.info_msg("No history recorded yet.")); return

    print(f"\n  {ui._c('secondary')}Last {len(entries)} operations:{ui._reset()}\n")
    for e in entries:
        ts      = e.get("ts","")[:19].replace("T"," ")
        action  = e.get("action","?")
        details = e.get("details", {})

        if action == "ADD":
            detail_str = f"{details.get('name','?')}  {ui._fmt_size(details.get('size',0))}"
            if details.get("compression","none") != "none":
                detail_str += f"  [{details['compression']}]"
        elif action in ("REMOVE","GET"):
            detail_str = details.get("name","?")
        elif action == "RENAME":
            detail_str = f"{details.get('old','?')} → {details.get('new','?')}"
        elif action in ("TAG_ADD","TAG_REMOVE","TAG_SET"):
            detail_str = f"{details.get('name','?')}  {', '.join('#'+t for t in details.get('tags',[]))}"
        elif action == "PASSWD_CHANGE":
            detail_str = "(password changed)"
        elif action in ("CP_IN","CP_OUT"):
            other = details.get("from") or details.get("to","?")
            detail_str = f"{details.get('name','?')}  ↔  {other}"
        elif action == "DESC_SET":
            detail_str = f"({details.get('length',0)} chars)"
        elif action == "EDIT":
            detail_str = f"{details.get('name','?')}  {ui._fmt_size(details.get('size',0))}"
        else:
            detail_str = json.dumps(details) if details else ""

        action_col = {
            "ADD":          ui._c("success"),
            "EDIT":         ui._c("success"),
            "REMOVE":       ui._c("error"),
            "GET":          ui._c("primary"),
            "RENAME":       ui._c("secondary"),
            "PASSWD_CHANGE":ui._c("warning"),
            "COMPACT":      ui._c("muted"),
            "VAULT_CREATED":ui._c("accent"),
            "DESC_SET":     ui._c("accent"),
        }.get(action, ui._c("muted"))

        print(
            f"  {ui._c('muted')}{ts}{ui._reset()}  "
            f"{action_col}{action:<16}{ui._reset()}"
            f"  {ui._c('primary')}{detail_str}{ui._reset()}"
        )
    print()

# need json for history detail_str fallback
import json


# ─── Phase 3: Compression setting ────────────────────────────────────────────

def cmdCompress(args: list):
    """
    compress              show current vault default compression
    compress zstd         set vault default to zstd
    compress zlib         set vault default to zlib
    compress none         disable compression (default)
    """
    if not _requireOpen(): return
    if not args:
        current = current_vault._meta.get("compression","none")
        print(ui.info_msg(f"Vault default compression: {current}  (options: zstd · zlib · none)"))
        return
    algo = args[0].lower()
    if algo not in ("zstd","zlib","none"):
        print(ui.error("Options: zstd · zlib · none")); return
    current_vault._meta["compression"] = algo
    current_vault._appendHistory("COMPRESS_SET", {"algorithm": algo})
    current_vault._flush()
    print(ui.success(f"Vault default compression set to '{algo}'."))
    if algo == "zstd":
        try:
            import zstandard  # noqa
        except ImportError:
            print(ui.warn("zstandard not installed — will fall back to zlib.\n"
                          "  Install it with:  pip install zstandard"))


# ─── Edit / create text file inside vault ────────────────────────────────────

def cmdFileEdit(args: list):
    """
    edit <n>             create a new text file and open in $EDITOR
    edit <# or name>     open existing vault file for editing

    Opens $VISUAL / $EDITOR / nano / vi. The file never touches disk unencrypted
    except as a temp file for the duration of the editor session. The temp file
    is deleted immediately after the editor closes regardless of outcome.

    Examples:
      edit notes.txt          create (or open) notes.txt
      edit 2                  edit stored file #2
      edit "my diary.md"      spaces OK — use quotes
    """
    if not _requireOpen(): return
    if not args:
        print(ui.error(
            "Usage: edit <n>          — create or open a text file\n"
            "       edit <# or name>  — edit existing stored file"
        ))
        return

    query = " ".join(args)

    # Resolve: existing entry by number or name, or treat as new filename
    existing = current_vault.findEntry(query)
    if existing is not None:
        # Editing an existing file — check it's text first
        if existing.get("mime") in {"IMG", "VID", "AUD", "ZIP", "BIN", "PDF"}:
            print(ui.warn(
                f"'{existing['name']}' is a {existing.get('mime','binary')} file.\n"
                f"  Binary files can't be edited as text — use  get  to extract it."
            ))
            return
        name = existing["name"]
        _printStep(f"Decrypting {name}…")
        try:
            initial = current_vault.viewFile(existing)
        except Exception as e:
            print(ui.error(f"Could not read '{name}': {e}")); return
    else:
        # New file — use the query string as the filename
        name    = query if "." in query else query + ".txt"
        initial = ""

    action = "Editing" if existing else "Creating"
    print(ui.info_msg(f"{action}  {name}  (opens in $EDITOR)"))

    try:
        entry = current_vault.editFile(name, initial_content=initial)
        size_str = ui._fmt_size(entry.get("size", 0))
        print(ui.success(f"Saved  '{entry['name']}'  ({size_str})"))
    except RuntimeError as e:
        print(ui.error(str(e)))
    except Exception as e:
        print(ui.error(f"Edit failed: {e}"))


# ─── Vault description ────────────────────────────────────────────────────────

def cmdDescribe(args: list):
    """
    describe                     show vault description
    describe <text>              set vault description inline
    describe --edit              open $EDITOR to write a longer description
    describe --clear             remove description
    """
    if not _requireOpen(): return

    if not args:
        desc = current_vault.getDescription()
        if desc:
            print(f"\n  {ui._c('secondary')}Description:{ui._reset()}")
            for line in desc.splitlines():
                print(f"  {line}")
            print()
        else:
            print(ui.info_msg("No description set.  Use  describe <text>  to add one."))
        return

    if args[0] == "--clear":
        current_vault.setDescription("")
        print(ui.success("Description cleared."))
        return

    if args[0] == "--edit":
        import tempfile, subprocess, os as _os
        current = current_vault.getDescription()
        tmp = None
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False,
            prefix="kvault_desc_", encoding="utf-8"
        ) as tf:
            tf.write(current)
            tmp = tf.name
        new_desc = ""
        try:
            editor = _os.environ.get("VISUAL") or _os.environ.get("EDITOR") or "nano"
            try:
                subprocess.run([editor, tmp], check=False)
            except FileNotFoundError:
                try: subprocess.run(["vi", tmp], check=False)
                except FileNotFoundError:
                    print(ui.error("No editor found. Set $EDITOR or use: describe <text>"))
                    return
            new_desc = open(tmp, encoding="utf-8").read().strip()
        finally:
            # 3-pass wipe then delete the temp description file
            if tmp and _os.path.exists(tmp):
                try:
                    size = _os.path.getsize(tmp)
                    with open(tmp, "r+b") as wf:
                        for val in (b"\x00", b"\xff", b"\x00"):
                            wf.seek(0); wf.write(val * size)
                    _os.unlink(tmp)
                except Exception:
                    try: _os.unlink(tmp)
                    except: pass
        if new_desc:
            current_vault.setDescription(new_desc)
            print(ui.success("Description saved."))
        return

    # Inline: describe This is my secret archive
    text = " ".join(args)
    current_vault.setDescription(text)
    print(ui.success(f"Description set: {text}"))


# ─── Theme commands ──────────────────────────────────────────────────────────

def cmdTheme(args: list):
    from src import theme as theme_mod
    if not args or args[0] == "list": ui.renderThemeList(); return
    sub = args[0]
    if sub == "set":
        if len(args) < 2: print(ui.error("Usage: theme set <n>")); return
        if theme_mod.setTheme(args[1]): print(ui.success(f"Theme set to '{args[1]}'."))
        else: print(ui.error(f"Unknown theme: {args[1]}"))
    elif sub == "preview": ui.renderThemePreview(args[1] if len(args) > 1 else None)
    elif sub == "bar":
        if len(args) < 2: print(ui.error("Usage: theme bar <style>")); return
        if theme_mod.setBar(args[1]): print(ui.success(f"Bar style set to '{args[1]}'."))
        else: print(ui.error(f"Unknown style: {args[1]}"))
    else: print(ui.error(f"Unknown theme subcommand: {sub}"))


# ─── Internal helpers ────────────────────────────────────────────────────────

def _suggestFiles(query: str):
    if current_vault is None or not current_vault._index: return
    q = query.lower()
    close = [e["name"] for e in current_vault._index if q[:3] in e["name"].lower()][:3]
    if close:
        names = "  ·  ".join(ui._c("primary") + n + ui._reset() for n in close)
        print(f"  {ui._c('muted')}→  Similar names: {ui._reset()}{names}")
