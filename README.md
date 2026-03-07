<div align="center">

# 🔐 KVAULT

### Encrypted File Vault

[![Version](https://img.shields.io/badge/version-2.0.0-blue)](https://github.com/heresalord/kvault/releases)
[![Crypto](https://img.shields.io/badge/crypto-AES--256--GCM-green)](#)
[![KDF](https://img.shields.io/badge/KDF-Argon2id-yellow)](#)
[![MAC](https://img.shields.io/badge/MAC-HMAC--SHA256-orange)](#)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)](#)
[![License](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

> **Local-first. Zero-knowledge. No network. No cloud. No trust required.**

</div>

---

KVAULT is a terminal-based encrypted file vault. Every file is encrypted with **AES-256-GCM** before it touches disk, keys are derived with **Argon2id**, and the entire vault is protected by an **HMAC-SHA256** integrity signature. Your master password never leaves your machine — not even a hash of it.

## ⚡ One-Line Install

```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/heresalord/kvault/main/install.sh | sh

# Windows (PowerShell — run as Administrator)
irm https://raw.githubusercontent.com/heresalord/kvault/main/install.ps1 | iex
```

> **Requirements:** Rust ≥ 1.70 (recommended), or Python 3.10+, or a C toolchain with libsodium.  
> See [Installation](#installation) for manual setup.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
- [Security Model](#security-model)
- [File Format](#file-format)
- [Architecture](#architecture)
- [Development Phases](#development-phases)
- [FAQ](#faq)

---

## Installation

KVAULT v2 has **no managed runtime dependency**. Choose the implementation that fits your environment:

| Language | Binary | Key Advantage | mlock Support |
|---|---|---|:---:|
| **Rust** *(recommended)* | `kvault` (single static binary) | Memory safety, zero GC, no runtime install | ✅ |
| **C** *(portable)* | `kvault` (gcc/clang) | Maximum portability, zero dependencies beyond libsodium | ✅ |
| **Python 3.10+** | `kvault.py` / pyinstaller bundle | Easiest audit surface | ✅ |

### Rust (Recommended)

```bash
cargo build --release
cp target/release/kvault /usr/local/bin/kvault   # Linux/macOS
# Windows: copy target\release\kvault.exe to a directory in %PATH%
```

### C

```bash
make                  # links against libsodium
sudo make install
```

### Python

```bash
pip install argon2-cffi cryptography
python kvault.py

# Or build a standalone bundle:
pyinstaller --onefile kvault.py
```

### Windows (Rust)

```powershell
# Install Rust via https://rustup.rs
cargo build --release
# Output: target\release\kvault.exe
```

---

## Quick Start

```
kvault                          # launch the REPL

kvault › new MyVault            # create a vault — prompts for password + recovery phrase
kvault › open MyVault           # open by name
kvault › add ~/Documents/secret.pdf
kvault › add ~/photos/id.jpg ~/keys/ssh.pem
kvault › add --recursive ~/Documents/folder
kvault › ls                     # list encrypted files
kvault › get 1                  # decrypt & extract file #1 to cwd
kvault › view 2                 # preview a text file without extracting
kvault › cat 2                  # alias for view
kvault › rename 1 new_name.pdf  # rename stored file
kvault › cp 1 OtherVault        # copy file to another vault
kvault › export ~/dump/         # decrypt all files to a folder
kvault › lock                   # wipe key from RAM (mlock + 3-pass wipe)
kvault › unlock                 # re-enter password to resume
kvault › exit                   # auto-locks on exit
```

---

## Command Reference

Full descriptions, notes, and examples for every command are in **[KVAULT_Command_Reference.docx](docs/KVAULT_Command_Reference.docx)**.

### Vault Management

| Command | Description |
|---|---|
| `vaults [path]` | Scan machine for `.kvault` files; cache results for `open <#>` |
| `new <name>` | Create an encrypted vault; prompts for password + optional recovery phrase |
| `open <name\|#\|path>` | Open vault by name, number from last `vaults` listing, or absolute path |
| `close` | Close vault and wipe all key material from memory |
| `lock` | Wipe keys (3-pass); vault path remembered for `unlock` |
| `unlock` | Re-enter password to resume a locked vault |
| `delete` | Overwrite and permanently delete the vault file |
| `passwd` | Change master password; re-derives keys and re-encrypts all blobs |
| `check` | Full integrity audit: HMAC → index → every per-file auth tag |
| `info` | Vault metadata, crypto params, live vs dead byte stats |
| `compact` | Discard dead frames and rewrite vault; auto-runs at 25% dead bytes |
| `upgrade <file>` | Migrate v1/v2 vault to v3; backs up original as `.v2bak` |

### File Operations

| Command | Description |
|---|---|
| `add <path> [path2…]` | Encrypt and store files; supports multi-file, directories, drag-drop |
| `add --recursive <dir>` | Recursively add all files in a directory tree |
| `ls` | List all stored files with number, size, type, and date |
| `get <# or name>` | Decrypt and extract file to current working directory |
| `view <# or name>` | Preview text file in terminal without writing to disk |
| `cat <# or name>` | Alias for `view` |
| `rm <# or name>` | Remove file from vault (blob reclaimed on next `compact`) |
| `rename <# or name> <new-name>` | Rename a stored file without re-encrypting the blob |
| `cp <# or name> <VaultName>` | Copy file to another open vault, re-encrypting in transit |
| `export <dest-dir>` | Decrypt all files to a folder; requires password confirmation |

### Theme & Display

| Command | Description |
|---|---|
| `theme list` | Show available themes with colour swatches |
| `theme set <name>` | Switch theme (`dark` · `light` · `ocean` · `forest` · `rose` · `mono`) |
| `theme preview [name]` | Preview a theme without switching |
| `theme bar <style>` | Set progress bar style (`block` · `shade` · `line` · `ascii` · `dot` · `pipe`) |

### General

| Command | Description |
|---|---|
| `help` | Display command reference in the terminal |
| `clear` | Clear screen and redraw the smart dashboard |
| `exit` / `quit` | Lock vault and exit the REPL |

---

## Security Model

### Four Independent Tamper-Detection Layers

All four layers must pass before a vault opens:

| # | Layer | Scope | Mechanism |
|:---:|---|---|---|
| 1 | Per-file AES-GCM auth tag | Each encrypted blob | 128-bit GCM tag — decryption fails on any byte change |
| 2 | AES-GCM auth tag on index | Encrypted file index | Modified index detected before any blob is read |
| 3 | AES-GCM auth tag on sentinel | Password verification | `KVAULT_OK_v3` encrypted with `encKey` — wrong password = instant fail |
| 4 | HMAC-SHA256 over entire file | Whole vault file | Covers header + sentinel + index + all frames |

### Key Derivation

```
password + salt
    │
    ▼  Argon2id (type=2, memory=64 MB, time=3, threads=4, hash=32 B)
    │
masterKey (256-bit)
    │
    ├─▶ HKDF-Extract('KVAULT_ENC_KEY_v2') ──▶ encKey  (AES-256-GCM)
    │
    └─▶ HKDF-Extract('KVAULT_MAC_KEY_v2') ──▶ macKey  (HMAC-SHA256)
```

### Memory Safety

KVAULT v2 drops Node.js specifically to gain direct memory control:

- **`mlock(2)` / `VirtualLock()`** — key pages are locked in RAM so the OS cannot page them to swap
- **3-pass wipe** — key bytes overwritten `0x00 → 0xFF → 0x00` on lock; `SecureZeroMemory` on Windows
- **Plaintext wiped after use** — immediately after encryption (`add`) or after disk write (`get`)
- **Auto-lock** — after 5 minutes of inactivity (configurable via `AUTO_LOCK_SECONDS`)

### Brute-Force Protection

Two independent layers:

**Session (resets on restart):**

| Attempts | Delay |
|:---:|:---:|
| 1–2 | 1 s |
| 3–4 | 3 s |
| 5–9 | 10 s |
| 10+ | 60 s hard lockout |

**Persisted counter (survives restarts):**

| Attempts | Effect |
|:---:|---|
| 1–4 | Normal |
| 5–9 | 10 s delay written to disk |
| 10–19 | 60 s delay on every open |
| 20+ | **FROZEN** — requires recovery phrase |

---

## File Format

Every vault is a single self-contained `.kvault` binary file.

```
┌──────────────────────────────────────────────────────────┐
│ MAGIC         4 B    'KVLT'                              │
│ FORMAT_VER    1 B    0x03                                │
│ FLAGS         2 B    feature flags (reserved)            │
│ SALT         32 B    random, unique per vault            │
│ SENT_LEN      4 B    uint32 big-endian                   │
│ SENTINEL      N B    enc(KVAULT_OK_v3, encKey)           │
│ IDX_LEN       4 B    uint32 big-endian                   │
│ ENC_INDEX     N B    enc(JSON index, encKey)             │
│ ─────── append-only frame log ─────────────────────────  │
│   FRAME_TYPE  1 B    0x01=ADD  0x02=REMOVE  0x03=RENAME  │
│   BLOB_ID    32 B    hex string                          │
│   BLOB_LEN    4 B    uint32 big-endian                   │
│   BLOB        N B    enc(plaintext, encKey) or empty     │
│ ─────────────────────────────────────────────────────── │
│ HMAC         32 B    HMAC-SHA256(macKey, all above)      │
└──────────────────────────────────────────────────────────┘
```

Key properties:
- **Append-only log** — mutations are appended as typed frames; no full-file rewrite on every add
- **Atomic compaction** — temp file + rename; a crash mid-compaction cannot corrupt the previous vault
- **Random IV per blob** — fresh 12-byte IV per `encryptBuffer` call; identical files produce different ciphertext
- **Self-describing** — format version byte allows forward-compatible migration

---

## Architecture

| File | Responsibility |
|---|---|
| `main.rs` / `main.c` / `kvault.py` | Entry point, REPL loop, command dispatch, auto-lock timer |
| `src/commands.*` | All command handlers, `promptPassword()`, brute-force protection, persisted counter |
| `src/vault.*` | `Vault` struct — `create()`, `open()`, `lock()`, `addFile()`, `compactVault()`, frame append |
| `src/crypto.*` | `encryptBuffer()`, `decryptBuffer()`, `deriveKey()`, `mlock` wrappers, `wipe()` |
| `src/ui.*` | Dashboard renderer, file list, fuzzy command suggestions, `promptStr()` |
| `src/theme.*` | Theme definitions, `loadTheme()`, `setTheme()`, config persistence |
| `src/config.*` | Constants: `ARGON2_CONFIG`, `IV_BYTES`, `SALT_BYTES`, `AUTO_LOCK_SECONDS`, `COMPACT_THRESHOLD` |

---

## Development Phases

### ✅ Phase 1 — Secure Core + Full CLI *(complete)*
AES-256-GCM encryption · Argon2id KDF · HMAC-SHA256 vault integrity · 4-layer tamper detection · 3-pass memory wipe · Atomic writes · Full REPL · Brute-force protection · 6 themes · `check` and `upgrade` commands

### 🔜 Phase 2 — v2 Migration *(current)*
Drop Node.js → Rust / C / Python · `mlock` / `VirtualLock` on key pages · Append-only log + compaction · Windows support · Persisted attempt counter + FROZEN state · Recovery phrase · `rename`, `cp`, `cat`, `export`, `compact` commands · Configurable Argon2id params · Clipboard auto-clear · Format v3

### 🗓 Phase 3 — Power Features *(planned)*
`tags` system · `search` command · zstd/deflate compression · `diff` command · Glob patterns for `add` · `history` command · Padding obfuscation

### 🚫 Out of Scope

| Feature | Reason |
|---|---|
| GUI / web interface | Defeats simplicity; introduces browser attack surface |
| Cloud sync | Requires trusting a third party with the vault file |
| Multi-user vaults | Requires key distribution infrastructure |
| Full password recovery | Zero-knowledge means no recovery — by design |

---

## FAQ

**What happens if I forget my password?**  
If you set a recovery phrase at vault creation, you can unfreeze the vault after 20 failed attempts using that phrase. Without a recovery phrase, the data is permanently unrecoverable.

**Can I move my `.kvault` file to another computer?**  
Yes. The vault is fully self-contained and portable. Copy it anywhere and open with `open /path/to/file.kvault`.

**Why not Node.js?**  
Node.js allocates key buffers through V8's heap. The GC can copy key material during compaction, leaving traces in memory. Crucially, you cannot call `mlock()` on V8-managed allocations — key pages may be paged to swap. A native binary gives full control over memory layout and page-locking.

**What does "3-pass memory wipe" mean?**  
Key bytes are overwritten three times: `0x00 → 0xFF → 0x00`. On Linux/macOS a compiler barrier prevents optimisation-out. On Windows `SecureZeroMemory()` is used. Pages are then `munlock`'d / `VirtualUnlock`'d.

**What if the vault file is corrupted?**  
The HMAC-SHA256 check fails immediately on open. The `check` command identifies which individual blobs are affected. Healthy files can still be extracted even if some blobs are corrupted.

---

<div align="center">

**KVAULT v2.0.0** · KMS Studio · Built 2026

AES-256-GCM · Argon2id · HMAC-SHA256 · Zero-Knowledge · Local-First

</div>
