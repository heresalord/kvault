<div align="center">

# 🔐 KVAULT

### Encrypted File Vault

![Version](https://img.shields.io/badge/version-3.0.0-blue)
![Crypto](https://img.shields.io/badge/crypto-AES--256--GCM-green)
![KDF](https://img.shields.io/badge/KDF-Argon2id-yellow)
![MAC](https://img.shields.io/badge/MAC-HMAC--SHA256-orange)
![Python](https://img.shields.io/badge/python-%3E%3D3.10-brightgreen)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

> **Local-first. Zero-knowledge. No network. No cloud. No trust required.**

</div>

---

## One-Line Install

**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/KMSStudio/kvault/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/KMSStudio/kvault/main/install.ps1 | iex
```

After install, launch from any terminal:
```bash
kvault
```

---

## Manual Install

**Requirements:** Python ≥ 3.10, pip. No other global dependencies.

```bash
# 1. Clone
git clone https://github.com/KMSStudio/kvault.git
cd kvault

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Register the global 'kvault' command (run once)
python kvault.py install

# 4. Launch
kvault
```

> `python kvault.py install` only needs to be run once per machine. It installs a shell launcher at `/usr/local/bin/kvault` (macOS/Linux) or adds the script to your PATH (Windows).

---

## Quick Start

```
kvault › new MyVault              # create vault — prompts for password
kvault › open MyVault             # open by name
kvault › add ~/Documents/secret.pdf
kvault › add ~/photos/*.jpg       # glob patterns supported
kvault › ls                       # list encrypted files
kvault › get 1                    # decrypt & extract file #1 to cwd
kvault › view 2                   # preview a text file without extracting
kvault › edit notes.txt           # create / edit a text file inside the vault
kvault › describe My archive      # add a description to the vault
kvault › search passport          # search by name, tag, type, or date
kvault › tags add 1 work,id       # tag a file
kvault › diff 1 2                 # compare two text files
kvault › history                  # view tamper-evident operation log
kvault › lock                     # wipe key from RAM (3-pass)
kvault › unlock                   # re-enter password
kvault › exit                     # auto-locks on exit
```

---

## Security Model

| Layer | Mechanism |
|-------|-----------|
| Per-file encryption | AES-256-GCM with 128-bit auth tag per blob |
| Key derivation | Argon2id (64 MB · 3 iterations · 4 threads · 256-bit output) |
| Sub-key split | HMAC-SHA256 domain separation — separate `encKey` and `macKey` |
| Vault integrity | HMAC-SHA256 over the entire vault file |
| Padding | PKCS#7 padding to 512-byte boundary — hides exact file sizes |
| Memory wipe | 3-pass overwrite (0x00 → 0xFF → 0x00) on lock |
| Atomic writes | Temp file + rename — crash-safe, previous version always intact |
| Brute-force | Progressive delays (1s/3s/10s) + 60s session lockout |
| Persisted lockout | Attempt counter survives restarts; FROZEN state after 20 failures |
| Auto-lock | 5-minute inactivity timer (configurable) |
| Tamper-evident log | HMAC-SHA256 chained history of all operations |

### What KVAULT does NOT do

- ❌ No network requests — ever
- ❌ No telemetry or analytics
- ❌ No password hints or unprotected recovery
- ❌ No cloud sync

---

## Features

### Core (Phase 1 & 2)
- AES-256-GCM encryption with fresh random IV per file
- Argon2id key derivation with configurable memory/time parameters
- 4-layer tamper detection (per-blob, index, sentinel, full-file HMAC)
- Append-only vault log with automatic compaction
- Full REPL with readline history, live prompt, fuzzy command suggestions
- 6 colour themes · 6 progress bar styles
- `open` by name, number, or absolute path
- Recovery phrase support for FROZEN vaults
- Cross-vault file copy (`cp`)
- Clipboard auto-clear after `view`

### Phase 3
- **Tags** — attach searchable labels to files (`tags add/rm/set/list`)
- **Search** — full-text search across name, tags, MIME type, date (AND logic)
- **Edit** — create and edit text files directly inside the vault
- **Diff** — colour-coded unified diff between two vault text files
- **History** — HMAC-chained tamper-evident log of all operations
- **Compression** — optional zstd/zlib per-file, only if smaller
- **Padding** — PKCS#7 padding hides exact file sizes from observers
- **Glob patterns** — `add ~/Documents/*.pdf`
- **Vault description** — human-readable label shown on dashboard

---

## Command Reference

Full documentation is available in [`KVAULT_Command_Reference.docx`](./KVAULT_Command_Reference.docx).

Quick reference — type `help` inside the REPL for the full list.

| Category | Commands |
|----------|----------|
| **Vault** | `new` `open` `close` `lock` `unlock` `delete` `passwd` `check` `info` `describe` `compact` `upgrade` `vaults` |
| **Files** | `add` `ls` `get` `view` `cat` `edit` `touch` `rename` `cp` `rm` `export` |
| **Tags** | `tags list` `tags add` `tags rm` `tags set` |
| **Search** | `search` |
| **Diff** | `diff` |
| **History** | `history` `history verify` |
| **Compression** | `compress` |
| **Theme** | `theme list` `theme set` `theme preview` `theme bar` |
| **General** | `help` `clear` `install` `exit` |

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `argon2-cffi` | Argon2id key derivation |
| `cryptography` | AES-256-GCM encryption |
| `zstandard` *(optional)* | Zstd compression (`pip install zstandard`) |

All other cryptographic primitives (HMAC-SHA256, random bytes) use Python's built-in `hashlib`, `hmac`, and `os` modules.

---

## Vault File Format

Every vault is a single self-contained `.kvault` file — fully portable. Copy it to any machine, USB drive, or cloud storage. The password is the only thing that isn't in the file.

```
MAGIC(4) | FORMAT_VER(1) | FLAGS(2) | SALT(32)
SENT_LEN(4) | SENTINEL(N)       ← AES-GCM encrypted KVAULT_OK_v3
IDX_LEN(4)  | ENC_INDEX(N)      ← AES-GCM encrypted JSON index
[FRAME_TYPE(1) | BLOB_ID(32) | BLOB_LEN(4) | BLOB(N)] * M
HMAC(32)                         ← HMAC-SHA256 over everything above
```

---

<div align="center">

**KVAULT v3.0.0** · KMS Studio

AES-256-GCM · Argon2id · HMAC-SHA256 · Zero-Knowledge · Local-First

</div>
