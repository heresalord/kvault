"""
KVAULT UI Layer  —  Phase 3
"""

import os
import shutil
from pathlib import Path

from src.theme import getTheme, getBar, THEMES, BAR_STYLES
from src.config import VERSION


def _c(key: str) -> str:
    return getTheme().get(key, "")

def _reset() -> str:
    return getTheme()["reset"]

def _fmt_size(n: int) -> str:
    if n < 1024:       return f"{n} B"
    if n < 1024**2:    return f"{n/1024:.1f} KB"
    if n < 1024**3:    return f"{n/1024**2:.1f} MB"
    return f"{n/1024**3:.1f} GB"

def _term_width() -> int:
    return shutil.get_terminal_size((80, 24)).columns

def _div(char="─") -> str:
    return _c("muted") + char * min(_term_width(), 70) + _reset()

def _ext(filename: str) -> str:
    suffix = Path(filename).suffix
    return suffix.lstrip(".").upper()[:5] if suffix else "—"


LOGO = r"""
  ██╗  ██╗██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗
  ██║ ██╔╝██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝
  █████╔╝ ██║   ██║███████║██║   ██║██║     ██║
  ██╔═██╗ ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║
  ██║  ██╗ ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║
  ╚═╝  ╚═╝ ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝
"""


def renderDashboard(vaults_in_cwd: list):
    os.system("clear" if os.name != "nt" else "cls")
    print(_c("logo") + LOGO + _reset())
    print(_c("muted") + f"  v{VERSION}  ·  AES-256-GCM · Argon2id · HMAC-SHA256\n" + _reset())
    print(_div())
    if vaults_in_cwd:
        print(_c("secondary") + "\n  Vaults in this directory:\n" + _reset())
        for i, v in enumerate(vaults_in_cwd, 1):
            print(f"  {_c('primary')}{i}.{_reset()}  {v}")
    else:
        print(_c("muted") + "\n  No vaults found in this directory.\n" + _reset())
    print()
    print(_div())
    _hint("open <#|name|path>",      "open a vault")
    _hint("open --tofolder <n>",     "find & open a vault in a folder")
    _hint("vaults",                  "list all vaults on this machine")
    _hint("new <n>",                 "create a new vault")
    _hint("help",                    "all commands")
    print()


def renderVaultDashboard(vault, recent: int = 8):
    os.system("clear" if os.name != "nt" else "cls")
    locked = vault.is_locked
    status = (
        _c("locked") + "● locked" + _reset()
        if locked
        else _c("unlocked") + "● unlocked" + _reset()
    )
    info   = vault.info()
    frozen = info.get("frozen", False)
    header = (
        f"  {status}   "
        f"{_c('bold')}{vault.name}{_reset()}"
    )
    if not locked:
        header += (
            f"   {_c('secondary')}{info['file_count']} "
            f"file{'s' if info['file_count'] != 1 else ''}   "
            f"{_fmt_size(info['total_size'])}{_reset()}"
        )
    if frozen:
        header += f"   {_c('error')}FROZEN{_reset()}"

    if not locked:
        extras = []
        if info.get("tag_count", 0) > 0:
            extras.append(f"{info['tag_count']} tag{'s' if info['tag_count']!=1 else ''}")
        if info.get("compressed_files", 0) > 0:
            extras.append(f"{info['compressed_files']} compressed")
        if extras:
            header += f"   {_c('muted')}{' · '.join(extras)}{_reset()}"

    print(_c("logo") + LOGO + _reset())
    print(header)

    # Description — shown when unlocked if set
    if not locked:
        desc = info.get("description", "").strip()
        if desc:
            print()
            for line in desc.splitlines():
                print(f"  {_c('muted')}{line}{_reset()}")

    print()
    print(_div())

    if locked:
        # ── LOCKED: don't reveal any file information ──────────────────────
        print()
        print(f"  {_c('muted')}File list hidden — vault is locked.{_reset()}")
        print()
        print(_div())
        _hint("unlock",   "re-enter password to unlock")
        _hint("close",    "close vault")
    else:
        # ── UNLOCKED: show recent files ────────────────────────────────────
        if vault._index:
            _printFileList(vault._index[:recent])
        else:
            print(_c("muted") + "\n  Vault is empty. Use  add <path>  to store files.\n" + _reset())
        print()
        print(_div())
        _hint("add <path|glob>",       "encrypt & store  (globs: *.pdf)")
        _hint("edit <n>",              "create or edit a text file")
        _hint("ls",                    "list all files")
        _hint("search <query>",        "search names, tags, type, date")
        _hint("get <# or name>",       "decrypt & extract")
        _hint("lock",                  "wipe key from memory")
    print()


def _hint(cmd: str, desc: str):
    print(f"  {_c('accent')}{cmd:<32}{_reset()}{_c('muted')}{desc}{_reset()}")


def _printFileList(entries: list):
    header = (
        f"  {_c('muted')}"
        f"{'#':<4}{'Name':<28}{'Ext':<7}{'Size':>9}  {'Type':<6}  {'Added':<12}"
        f"{_reset()}"
    )
    print(header)
    print(_div("·"))
    for i, e in enumerate(entries, 1):
        added     = e.get("added", "")[:10]
        name      = e["name"]
        ext       = _ext(name)
        disp_name = (name[:26] + "…") if len(name) > 27 else name
        tags      = e.get("tags", [])
        tag_str   = ""
        if tags:
            tag_str = "  " + "  ".join(
                _c("accent") + "#" + t + _reset() for t in tags[:3]
            )
            if len(tags) > 3:
                tag_str += f"  {_c('muted')}+{len(tags)-3}{_reset()}"
        comp = e.get("compression", "none")
        comp_mark = f" {_c('muted')}[{comp}]{_reset()}" if comp != "none" else ""
        print(
            f"  {_c('secondary')}{i:<4}{_reset()}"
            f"{_c('primary')}{disp_name:<28}{_reset()}"
            f"{_c('muted')}{ext:<7}{_reset()}"
            f"{_c('muted')}{_fmt_size(e.get('size', 0)):>9}  "
            f"{e.get('mime', 'BIN'):<6}  "
            f"{added:<12}{_reset()}"
            f"{comp_mark}{tag_str}"
        )


def renderFileList(vault):
    if not vault._index:
        print(_c("muted") + "  No files stored." + _reset())
        return
    _printFileList(vault._index)


def renderVaultList(vaults: list):
    if not vaults:
        print(_c("muted") + "\n  No .kvault files found.\n" + _reset())
        return
    print(_c("secondary") + "\n  Found vaults:\n" + _reset())
    for i, p in enumerate(vaults, 1):
        size = _fmt_size(Path(p).stat().st_size) if Path(p).exists() else "?"
        print(
            f"  {_c('primary')}{i}.{_reset()}  "
            f"{Path(p).stem:<28} "
            f"{_c('muted')}{size:>8}  {p}{_reset()}"
        )
    print()


HELP_TEXT = """
  VAULT MANAGEMENT
  ────────────────────────────────────────────────────────────────────────
  vaults [path]                      list all .kvault files on this machine
  new <n>                         create vault
    --memory <MB>                    Argon2id memory (default 64 MB)
    --time <N>                       Argon2id iterations (default 3)
    --recovery                       set a recovery phrase at creation
  open <name|#|path>                 open vault by name, number, or path
  open --tofolder <n>             search for folder & open vault inside
  close                              close vault & wipe keys
  lock                               lock vault (3-pass key wipe)
  unlock                             re-enter password to unlock
  delete                             permanently destroy vault
  passwd                             change master password
  check                              verify integrity of all stored files
  info                               vault metadata, crypto params, status
  describe <text>                    set vault description (shown on dashboard)
  describe --edit                    open $EDITOR to write a longer description
  describe --clear                   remove description
  desc                               alias for describe
  compact                            rewrite vault (discard dead frames)
  upgrade <file>                     migrate v1/v2 vault to v3

  FILE OPERATIONS
  ────────────────────────────────────────────────────────────────────────
  add <path|glob> [path2...]         encrypt & store (glob patterns supported)
  add --recursive <dir>              recursively add all files in directory
  add --compress zstd|zlib|none      compress before encryption
  add --tag tag1,tag2                attach tags at add time
  edit <n>                        create a new text file in the vault
  edit <# or name>                   open existing text file in $EDITOR
  touch <n>                       alias for edit
  ls                                 list all files (name, ext, size, type, tags)
  get <# or name>                    decrypt & extract to current directory
  get <# or name> --to <path>        extract to an exact path
  get <# or name> --tofolder <n>  search for folder by name, extract there
  view <# or name>                   preview text file in terminal
  cat <# or name>                    alias for view
  rename <# or name> <new-name>      rename a stored file
  cp <# or name> <TargetVault>       copy file into another vault
  rm <# or name>                     remove file from vault
  export <dest-dir>                  decrypt all files to a folder
  export --tofolder <n>           search for folder, export all there

  TAGS
  ────────────────────────────────────────────────────────────────────────
  tags list                          list all tags across all files
  tags list <# or name>              list tags on a specific file
  tags add  <# or name> <t1,t2>      add tags to a file
  tags rm   <# or name> <t1,t2>      remove specific tags from a file
  tags set  <# or name> <t1,t2>      replace all tags on a file

  SEARCH
  ────────────────────────────────────────────────────────────────────────
  search <query>                     search names, tags, MIME type, date
                                     (multiple words = AND logic)

  DIFF
  ────────────────────────────────────────────────────────────────────────
  diff <#|name> <#|name>             unified diff between two text files

  HISTORY
  ────────────────────────────────────────────────────────────────────────
  history [N]                        show last N operations (default 20)
  history verify                     verify HMAC chain integrity

  COMPRESSION
  ────────────────────────────────────────────────────────────────────────
  compress                           show vault default compression
  compress zstd|zlib|none            set vault default compression

  THEME & DISPLAY
  ────────────────────────────────────────────────────────────────────────
  theme list                         show available themes
  theme set <n>                   dark · light · ocean · forest · rose · mono
  theme preview [name]               preview current or named theme
  theme bar <style>                  block · shade · line · ascii · dot · pipe

  GENERAL
  ────────────────────────────────────────────────────────────────────────
  install                            install 'kvault' as a global command
  help                               show this reference
  clear                              clear screen & redraw dashboard
  exit / quit                        lock & exit
"""


def renderHelp():
    lines = HELP_TEXT.split("\n")
    for line in lines:
        stripped = line.strip()
        if not stripped:
            print()
        elif stripped.startswith("─"):
            print(_c("muted") + line + _reset())
        elif stripped.isupper() and any(
            stripped.endswith(w) for w in
            ("MANAGEMENT", "OPERATIONS", "DISPLAY", "GENERAL",
             "TAGS", "SEARCH", "DIFF", "HISTORY", "COMPRESSION")
        ):
            print(_c("accent") + line + _reset())
        elif stripped.startswith("--"):
            print(f"{_c('muted')}{line}{_reset()}")
        else:
            parts = line.split("  ", 1)
            if len(parts) == 2 and parts[0].strip():
                print(f"{_c('primary')}{parts[0]:<44}{_reset()}{_c('muted')}{parts[1].lstrip()}{_reset()}")
            else:
                print(_c("secondary") + line + _reset())


def renderThemeList():
    print()
    for name, t in THEMES.items():
        swatch = (
            t["primary"]   + "■ " + t["accent"]    + "■ " +
            t["secondary"] + "■ " + t["warning"]   + "■ " +
            t["error"]     + "■ " + t["reset"]
        )
        print(f"  {_c('primary')}{name:<10}{_reset()}{swatch}")
    print()


def renderThemePreview(name: str = None):
    t = THEMES.get(name) if name else getTheme()
    if not t:
        print(error(f"Unknown theme: {name}")); return
    r = t["reset"]
    print(f"\n  Preview: {t['primary']}{t['name']}{r}\n")
    print(
        f"  {t['primary']}primary{r}  {t['secondary']}secondary{r}  "
        f"{t['accent']}accent{r}  {t['warning']}warning{r}  "
        f"{t['error']}error{r}  {t['muted']}muted{r}"
    )
    filled, empty = getBar()
    print(f"\n  {t['accent']}{filled * 20 + empty * 10}{r}\n")


def success(msg: str) -> str:
    return _c("success") + "  ✓  " + _reset() + msg

def error(msg: str) -> str:
    return _c("error")   + "  ✗  " + _reset() + msg

def warn(msg: str) -> str:
    return _c("warning") + "  ⚠  " + _reset() + msg

def info_msg(msg: str) -> str:
    return _c("secondary") + "  ·  " + _reset() + msg


ALL_COMMANDS = [
    "vaults", "new", "open", "close", "lock", "unlock", "delete",
    "passwd", "check", "info", "compact", "upgrade", "install",
    "add", "ls", "get", "view", "cat", "edit", "touch", "rename", "cp", "rm", "export",
    "tags", "search", "diff", "history", "compress", "describe", "desc",
    "theme", "help", "clear", "exit", "quit",
]

def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b): return _levenshtein(b, a)
    if not b: return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]

def suggestCommand(typo: str) -> list:
    scored = [(cmd, _levenshtein(typo.lower(), cmd)) for cmd in ALL_COMMANDS]
    scored.sort(key=lambda x: x[1])
    return [cmd for cmd, dist in scored[:3] if dist <= 3]

def renderSuggestions(typo: str, suggestions: list):
    print(error(f"Unknown command: {typo}"))
    if suggestions:
        s = " · ".join(_c("primary") + s + _reset() for s in suggestions)
        print(f"  {_c('muted')}→  Did you mean: {_reset()}{s}")
