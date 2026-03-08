"""
KVAULT Vault Class  —  Phase 3 complete
-----------------------------------------
Phase 1 & 2 foundation:
  AES-256-GCM · Argon2id · HMAC-SHA256 · append-only log · atomic writes
  configurable Argon2id per vault · recovery phrase · FROZEN state
  rename · cp · export · compact

Phase 3:
  tags · search · compression · diff · glob · history · padding

Phase 3+:
  editFile()      — create or overwrite a text file inside the vault via $EDITOR
  setDescription() — vault-level description stored encrypted in _meta
"""

import os
import json
import struct
import hashlib
import hmac as hmac_mod
import time
import zlib
import difflib
import glob as _glob_mod
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Dict, Tuple

from src.config import (
    MAGIC, FORMAT_VERSION, SALT_BYTES, HMAC_BYTES,
    SENTINEL_PLAIN, FRAME_ADD, FRAME_REMOVE, FRAME_RENAME,
    ARGON2_CONFIG,
    PERSIST_WARN_THRESHOLD, PERSIST_DELAY_THRESHOLD, PERSIST_FROZEN_THRESHOLD,
    DEFAULT_COMPRESSION, PADDING_BLOCK_SIZE,
    HISTORY_MAX_ENTRIES, DIFF_MAX_BYTES,
)
from src.crypto import (
    encryptBuffer, decryptBuffer, deriveKey, deriveSubKeys,
    computeVaultHMAC, wipe,
)


# ─── Small utilities ─────────────────────────────────────────────────────────

def _pack_u32(n: int) -> bytes:
    return struct.pack(">I", n)

def _unpack_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]

def _blob_id_for(name: str) -> str:
    raw = f"{name}:{time.time_ns()}:{os.urandom(8).hex()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

_BINARY_MIMES = {"IMG", "VID", "AUD", "ZIP", "BIN", "PDF"}


# ─── Compression ─────────────────────────────────────────────────────────────

def _compress(data: bytes, algorithm: str) -> Tuple[bytes, str]:
    """Compress data. Only stores compressed version if it is actually smaller."""
    if algorithm == "zstd":
        try:
            import zstandard as zstd
            compressed = zstd.ZstdCompressor(level=3).compress(data)
            if len(compressed) < len(data):
                return compressed, "zstd"
        except ImportError:
            pass
        algorithm = "zlib"

    if algorithm == "zlib":
        compressed = zlib.compress(data, level=6)
        if len(compressed) < len(data):
            return compressed, "zlib"

    return data, "none"


def _decompress(data: bytes, algorithm: str) -> bytes:
    if algorithm == "zstd":
        import zstandard as zstd
        return zstd.ZstdDecompressor().decompress(data)
    if algorithm == "zlib":
        return zlib.decompress(data)
    return data


# ─── Padding  (hides exact blob size from hex-dump observers) ────────────────
# Uses a 2-byte little-endian length prefix instead of PKCS#7 so that block
# sizes larger than 255 bytes (e.g. 512) work correctly for any file size.

def _pad(data: bytes, block_size: int) -> bytes:
    """Pad data to next multiple of block_size, storing length in a 2-byte LE prefix."""
    if block_size <= 0:
        return data
    # +2 for the prefix itself
    padded_len = (len(data) + 2 + block_size - 1) // block_size * block_size
    pad_len    = padded_len - len(data) - 2
    prefix     = struct.pack("<H", pad_len)   # 2-byte LE: 0–65535 padding bytes
    return prefix + data + bytes(pad_len)


def _unpad(data: bytes, block_size: int) -> bytes:
    """Remove padding added by _pad."""
    if block_size <= 0 or len(data) < 2:
        return data
    pad_len = struct.unpack("<H", data[:2])[0]
    if 2 + pad_len > len(data):
        # Doesn't look like our padding — return as-is (legacy/unpadded blob)
        return data
    return data[2:len(data) - pad_len]


# ─── Glob expansion ──────────────────────────────────────────────────────────

def expandGlob(pattern: str) -> List[Path]:
    """Expand a glob/glob** pattern (with ~ expansion) to a list of files."""
    expanded = str(Path(pattern).expanduser())
    results  = _glob_mod.glob(expanded, recursive=True)
    return [Path(p) for p in sorted(results) if Path(p).is_file()]


# ─── History log (HMAC-chained) ──────────────────────────────────────────────

def _makeHistoryEntry(mac_key: bytes, action: str,
                      details: dict, prev_hmac: str) -> dict:
    entry = {
        "ts":      _now_iso(),
        "action":  action,
        "details": details,
        "prev":    prev_hmac,
    }
    canonical     = json.dumps(entry, sort_keys=True).encode("utf-8")
    entry["hmac"] = hmac_mod.new(mac_key, canonical, hashlib.sha256).hexdigest()
    return entry


def _verifyHistoryChain(mac_key: bytes,
                        entries: list) -> Tuple[bool, int]:
    """Returns (all_valid, first_broken_index); index = -1 if all valid."""
    for i, entry in enumerate(entries):
        stored   = entry.get("hmac", "")
        check    = {k: v for k, v in entry.items() if k != "hmac"}
        canon    = json.dumps(check, sort_keys=True).encode("utf-8")
        expected = hmac_mod.new(mac_key, canon, hashlib.sha256).hexdigest()
        if not hmac_mod.compare_digest(stored, expected):
            return False, i
    return True, -1


# ─── Vault ───────────────────────────────────────────────────────────────────

class Vault:

    def __init__(self):
        self.path: Optional[Path]          = None
        self.name: str                     = ""
        self._salt: Optional[bytes]        = None
        self._enc_key: Optional[bytearray] = None
        self._mac_key: Optional[bytearray] = None
        self._index:   list                = []
        self._blobs:   dict                = {}
        self._locked:  bool                = True
        self._meta:    dict                = {}
        self._history: list                = []

    # ── Create ───────────────────────────────────────────────────────────────

    @classmethod
    def create(cls, path: Path, password: str,
               argon2_override: dict = None,
               recovery_phrase: str = "") -> "Vault":
        v        = cls()
        v.path   = path
        v.name   = path.stem
        v._salt  = os.urandom(SALT_BYTES)

        cfg = dict(ARGON2_CONFIG)
        if argon2_override:
            cfg.update(argon2_override)

        master           = deriveKey(password, v._salt, cfg)
        enc_key, mac_key = deriveSubKeys(master)
        v._enc_key       = bytearray(enc_key)
        v._mac_key       = bytearray(mac_key)
        v._index         = []
        v._blobs         = {}
        v._history       = []
        v._locked        = False
        v._meta          = {
            "argon2":          cfg,
            "failed_attempts": 0,
            "frozen":          False,
            "compression":     DEFAULT_COMPRESSION,
            "description":     "",
        }
        if recovery_phrase:
            v._meta["recovery_hmac"] = hmac_mod.new(
                mac_key, recovery_phrase.encode(), hashlib.sha256
            ).hexdigest()

        v._appendHistory("VAULT_CREATED", {"name": v.name})
        v._flush()
        return v

    # ── Open ─────────────────────────────────────────────────────────────────

    @classmethod
    def open(cls, path: Path, password: str,
             recovery_phrase: str = "") -> "Vault":
        v      = cls()
        v.path = path
        v.name = path.stem
        v._parseAndVerify(path.read_bytes(), password,
                          recovery_phrase=recovery_phrase)
        v._locked = False
        return v

    def _parseAndVerify(self, raw: bytes, password: str,
                        recovery_phrase: str = ""):
        offset = 0
        if raw[offset:offset+4] != MAGIC:
            raise ValueError("Not a KVAULT file (bad magic bytes)")
        offset += 4

        fmt_ver = raw[offset]; offset += 1
        if fmt_ver not in (0x02, 0x03):
            raise ValueError(f"Unsupported format version: 0x{fmt_ver:02x}")
        if fmt_ver == 0x03:
            offset += 2   # FLAGS

        self._salt = raw[offset:offset+SALT_BYTES]; offset += SALT_BYTES

        master           = deriveKey(password, self._salt, dict(ARGON2_CONFIG))
        enc_key, mac_key = deriveSubKeys(master)
        self._enc_key    = bytearray(enc_key)
        self._mac_key    = bytearray(mac_key)

        # Whole-file HMAC
        expected = computeVaultHMAC(bytes(self._mac_key), raw[:-HMAC_BYTES])
        if not hmac_mod.compare_digest(expected, raw[-HMAC_BYTES:]):
            wipe(self._enc_key); wipe(self._mac_key)
            raise ValueError("HMAC failed — wrong password or tampered file")

        # Sentinel (password oracle)
        sent_len  = _unpack_u32(raw, offset); offset += 4
        sent_blob = raw[offset:offset+sent_len]; offset += sent_len
        try:
            plain = decryptBuffer(sent_blob, bytes(self._enc_key))
        except ValueError:
            wipe(self._enc_key); wipe(self._mac_key)
            raise ValueError("Wrong password")
        if plain != SENTINEL_PLAIN:
            wipe(self._enc_key); wipe(self._mac_key)
            raise ValueError("Wrong password")

        # Encrypted index
        idx_len  = _unpack_u32(raw, offset); offset += 4
        enc_idx  = raw[offset:offset+idx_len]; offset += idx_len
        idx_json = decryptBuffer(enc_idx, bytes(self._enc_key))
        parsed   = json.loads(idx_json)

        # Unpack: [meta, ...files..., history]
        self._meta = self._history = None
        files = []
        for item in parsed:
            if isinstance(item, dict) and item.get("_kvault_meta"):
                self._meta = item
            elif isinstance(item, dict) and item.get("_kvault_history"):
                self._history = item.get("entries", [])
            else:
                files.append(item)
        if self._meta is None:    self._meta    = {}
        if self._history is None: self._history = []
        self._index = files

        # FROZEN check
        if self._meta.get("frozen"):
            if not recovery_phrase:
                raise ValueError(
                    "FROZEN: vault locked after too many failed attempts. "
                    "Provide your recovery phrase."
                )
            expected_r = self._meta.get("recovery_hmac", "")
            if not expected_r:
                raise ValueError("FROZEN but no recovery phrase was set — data unrecoverable.")
            actual_r = hmac_mod.new(
                bytes(self._mac_key), recovery_phrase.encode(), hashlib.sha256
            ).hexdigest()
            if not hmac_mod.compare_digest(expected_r, actual_r):
                wipe(self._enc_key); wipe(self._mac_key)
                raise ValueError("Wrong recovery phrase.")
            self._meta["frozen"]          = False
            self._meta["failed_attempts"] = 0

        # Frame log (blobs)
        frame_end   = len(raw) - HMAC_BYTES
        self._blobs = {}
        while offset < frame_end:
            if offset + 37 > frame_end:
                break
            ftype   = raw[offset]; offset += 1
            blob_id = raw[offset:offset+32].decode("ascii").rstrip(); offset += 32
            blen    = _unpack_u32(raw, offset); offset += 4
            if offset + blen > frame_end:
                break
            blob = raw[offset:offset+blen]; offset += blen
            if ftype == FRAME_ADD:
                self._blobs[blob_id] = blob
            elif ftype == FRAME_REMOVE:
                self._blobs.pop(blob_id, None)

    # ── Lock / Unlock ────────────────────────────────────────────────────────

    def lock(self):
        if self._enc_key: wipe(self._enc_key)
        if self._mac_key: wipe(self._mac_key)
        self._enc_key = self._mac_key = None
        self._blobs   = {}
        self._locked  = True

    def unlock(self, password: str, recovery_phrase: str = ""):
        self._parseAndVerify(self.path.read_bytes(), password,
                             recovery_phrase=recovery_phrase)
        self._locked = False

    # ── Add file ─────────────────────────────────────────────────────────────

    def addFile(self, file_path: Path,
                tags: List[str] = None,
                compression: str = None) -> dict:
        self._requireUnlocked()
        algo      = compression or self._meta.get("compression", DEFAULT_COMPRESSION)
        plaintext = file_path.read_bytes()

        compressed, used_algo = _compress(plaintext, algo)
        buf = bytearray(plaintext); wipe(buf)

        padded = _pad(compressed, PADDING_BLOCK_SIZE)
        blob   = encryptBuffer(padded, bytes(self._enc_key))
        buf2   = bytearray(padded); wipe(buf2)

        blob_id = _blob_id_for(file_path.name)
        entry   = {
            "id":          blob_id,
            "name":        file_path.name,
            "size":        len(plaintext),
            "mime":        _guessMime(file_path.name),
            "added":       _now_iso(),
            "compression": used_algo,
            "tags":        sorted({t.lower().strip() for t in (tags or []) if t.strip()}),
        }
        self._index.append(entry)
        self._blobs[blob_id] = blob
        self._appendHistory("ADD", {
            "name": file_path.name, "size": len(plaintext),
            "compression": used_algo, "tags": entry["tags"],
        })
        self._flush()
        return entry

    # ── Extract file ─────────────────────────────────────────────────────────

    def extractFile(self, entry: dict, dest_dir: Path) -> Path:
        self._requireUnlocked()
        blob = self._blobs.get(entry["id"])
        if blob is None:
            raise FileNotFoundError(f"Blob not found for '{entry['name']}'")

        padded    = decryptBuffer(blob, bytes(self._enc_key))
        unpadded  = _unpad(padded, PADDING_BLOCK_SIZE)
        plaintext = _decompress(unpadded, entry.get("compression", "none"))

        dest_dir = Path(dest_dir).expanduser().resolve()
        dest_dir.mkdir(parents=True, exist_ok=True)
        out = dest_dir / entry["name"]
        out.write_bytes(plaintext)

        buf = bytearray(plaintext); wipe(buf)
        self._appendHistory("GET", {"name": entry["name"], "dest": str(dest_dir)})
        self._flush()
        return out

    # ── View file (text preview) ──────────────────────────────────────────────

    def viewFile(self, entry: dict) -> str:
        self._requireUnlocked()
        if entry.get("mime") in _BINARY_MIMES:
            raise ValueError(
                f"'{entry['name']}' is a {entry.get('mime','binary')} file — "
                f"cannot preview as text.\n  Use  get {entry['name']}  to extract it."
            )
        blob = self._blobs.get(entry["id"])
        if blob is None:
            raise FileNotFoundError(f"Blob not found for '{entry['name']}'")

        padded    = decryptBuffer(blob, bytes(self._enc_key))
        unpadded  = _unpad(padded, PADDING_BLOCK_SIZE)
        plaintext = _decompress(unpadded, entry.get("compression", "none"))

        try:
            text = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = plaintext.decode("latin-1")
            except Exception:
                buf = bytearray(plaintext); wipe(buf)
                raise ValueError(f"'{entry['name']}' is binary — use  get  to extract it.")

        buf = bytearray(plaintext); wipe(buf)
        non_print = sum(1 for c in text if ord(c) < 9 or (13 < ord(c) < 32))
        if text and non_print / len(text) > 0.15:
            raise ValueError(f"'{entry['name']}' appears binary — use  get  to extract it.")
        return text

    # ── Edit / create text file in vault ─────────────────────────────────────

    def editFile(self, name: str, initial_content: str = "") -> dict:
        """
        Create or overwrite a text file stored in the vault.
        Opens $VISUAL / $EDITOR / nano / vi for editing.
        Returns the updated (or new) index entry.
        """
        self._requireUnlocked()
        import tempfile
        import subprocess
        import os as _os

        suffix = Path(name).suffix or ".txt"

        # Write current content to temp file so editor opens with existing text.
        # Always delete & wipe in a finally block — even on crash or SIGTERM.
        tmp_edit = None
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False,
            prefix="kvault_edit_", encoding="utf-8"
        ) as tf:
            tf.write(initial_content)
            tmp_edit = tf.name

        new_content = ""
        try:
            # Open editor — prefer $VISUAL > $EDITOR > nano > vi
            editor = _os.environ.get("VISUAL") or _os.environ.get("EDITOR") or "nano"
            try:
                subprocess.run([editor, tmp_edit], check=False)
            except FileNotFoundError:
                try:
                    subprocess.run(["vi", tmp_edit], check=False)
                except FileNotFoundError:
                    raise RuntimeError(
                        "No terminal editor found (tried nano and vi). "
                        "Set $EDITOR to your preferred editor."
                    )
            new_content = Path(tmp_edit).read_text(encoding="utf-8")
        finally:
            # Wipe then delete the plaintext temp file regardless of outcome
            if tmp_edit and _os.path.exists(tmp_edit):
                try:
                    size = _os.path.getsize(tmp_edit)
                    with open(tmp_edit, "r+b") as wf:
                        for val in (b"\x00", b"\xff", b"\x00"):
                            wf.seek(0); wf.write(val * size)
                    _os.unlink(tmp_edit)
                except Exception:
                    try: _os.unlink(tmp_edit)
                    except: pass

        # Write to a second temp file so addFile can read it as a Path
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=suffix, delete=False,
            prefix="kvault_save_"
        ) as sf:
            sf.write(new_content.encode("utf-8"))
            tmp_save = Path(sf.name)

        try:
            existing = self.findEntry(name)
            if existing:
                old_tags = existing.get("tags", [])
                old_comp = existing.get("compression")
                self._index = [e for e in self._index if e["id"] != existing["id"]]
                self._blobs.pop(existing["id"], None)
                entry = self.addFile(tmp_save, tags=old_tags, compression=old_comp)
            else:
                entry = self.addFile(tmp_save)

            # Restore the intended name (addFile recorded the temp filename)
            for e in self._index:
                if e["id"] == entry["id"]:
                    e["name"] = name
                    break
            entry["name"] = name
        finally:
            try: tmp_save.unlink()
            except: pass

        self._appendHistory("EDIT", {"name": name, "size": len(new_content.encode())})
        self._flush()
        return entry

    # ── Remove ───────────────────────────────────────────────────────────────

    def removeFile(self, entry: dict):
        self._requireUnlocked()
        self._index = [e for e in self._index if e["id"] != entry["id"]]
        self._blobs.pop(entry["id"], None)
        self._appendHistory("REMOVE", {"name": entry["name"]})
        self._flush()

    # ── Rename ───────────────────────────────────────────────────────────────

    def renameFile(self, entry: dict, new_name: str):
        self._requireUnlocked()
        old = entry["name"]
        for e in self._index:
            if e["id"] == entry["id"]:
                e["name"] = new_name
                break
        self._appendHistory("RENAME", {"old": old, "new": new_name})
        self._flush()

    # ── Copy to another vault ─────────────────────────────────────────────────

    def copyFileTo(self, entry: dict, other: "Vault"):
        self._requireUnlocked()
        other._requireUnlocked()
        blob = self._blobs.get(entry["id"])
        if blob is None:
            raise FileNotFoundError(f"Blob not found for '{entry['name']}'")
        padded   = decryptBuffer(blob, bytes(self._enc_key))
        new_blob = encryptBuffer(padded, bytes(other._enc_key))
        buf = bytearray(padded); wipe(buf)

        new_entry           = dict(entry)
        new_entry["id"]     = _blob_id_for(entry["name"])
        new_entry["added"]  = _now_iso()
        other._index.append(new_entry)
        other._blobs[new_entry["id"]] = new_blob
        other._appendHistory("CP_IN",  {"name": entry["name"], "from": self.name})
        other._flush()
        self._appendHistory("CP_OUT", {"name": entry["name"], "to": other.name})
        self._flush()
        return new_entry

    # ── Export all ───────────────────────────────────────────────────────────

    def exportAll(self, dest_dir: Path):
        self._requireUnlocked()
        dest_dir = Path(dest_dir).expanduser().resolve()
        dest_dir.mkdir(parents=True, exist_ok=True)
        for entry in self._index:
            self.extractFile(entry, dest_dir)

    # ── Change password ──────────────────────────────────────────────────────

    def changePassword(self, new_password: str):
        self._requireUnlocked()
        new_salt         = os.urandom(SALT_BYTES)
        cfg              = self._meta.get("argon2", ARGON2_CONFIG)
        master           = deriveKey(new_password, new_salt, cfg)
        enc_key, mac_key = deriveSubKeys(master)

        new_blobs = {}
        for bid, blob in self._blobs.items():
            padded = decryptBuffer(blob, bytes(self._enc_key))
            new_blobs[bid] = encryptBuffer(padded, enc_key)
            buf = bytearray(padded); wipe(buf)

        self._meta.pop("recovery_hmac", None)
        wipe(self._enc_key); wipe(self._mac_key)
        self._salt    = new_salt
        self._enc_key = bytearray(enc_key)
        self._mac_key = bytearray(mac_key)
        self._blobs   = new_blobs
        self._appendHistory("PASSWD_CHANGE", {})
        self._flush()

    # ── Description ──────────────────────────────────────────────────────────

    def setDescription(self, text: str):
        """Set vault-level description. Stored encrypted in _meta."""
        self._requireUnlocked()
        self._meta["description"] = text.strip()
        self._appendHistory("DESC_SET", {"length": len(text.strip())})
        self._flush()

    def getDescription(self) -> str:
        return self._meta.get("description", "")

    # ── Tags ─────────────────────────────────────────────────────────────────

    def addTags(self, entry: dict, tags: List[str]) -> List[str]:
        self._requireUnlocked()
        new_tags = {t.lower().strip() for t in tags if t.strip()}
        for e in self._index:
            if e["id"] == entry["id"]:
                existing = set(e.get("tags", []))
                existing.update(new_tags)
                e["tags"] = sorted(existing)
                self._appendHistory("TAG_ADD", {"name": e["name"], "tags": sorted(new_tags)})
                self._flush()
                return e["tags"]
        raise KeyError(f"Entry not found: {entry.get('name')}")

    def removeTags(self, entry: dict, tags: List[str]) -> List[str]:
        self._requireUnlocked()
        rm = {t.lower().strip() for t in tags}
        for e in self._index:
            if e["id"] == entry["id"]:
                e["tags"] = [t for t in e.get("tags", []) if t not in rm]
                self._appendHistory("TAG_REMOVE", {"name": e["name"], "tags": sorted(rm)})
                self._flush()
                return e["tags"]
        raise KeyError(f"Entry not found: {entry.get('name')}")

    def setTags(self, entry: dict, tags: List[str]) -> List[str]:
        self._requireUnlocked()
        new_tags = sorted({t.lower().strip() for t in tags if t.strip()})
        for e in self._index:
            if e["id"] == entry["id"]:
                e["tags"] = new_tags
                self._appendHistory("TAG_SET", {"name": e["name"], "tags": new_tags})
                self._flush()
                return e["tags"]
        raise KeyError(f"Entry not found: {entry.get('name')}")

    def listAllTags(self) -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}
        for e in self._index:
            for tag in e.get("tags", []):
                result.setdefault(tag, []).append(e["name"])
        return dict(sorted(result.items()))

    # ── Search ───────────────────────────────────────────────────────────────

    def search(self, query: str) -> List[dict]:
        self._requireUnlocked()
        terms = query.lower().strip().split()
        if not terms:
            return list(self._index)
        out = []
        for e in self._index:
            searchable = " ".join([
                e["name"].lower(),
                " ".join(e.get("tags", [])),
                e.get("mime", "").lower(),
                e.get("added", "")[:10],
            ])
            if all(t in searchable for t in terms):
                out.append(e)
        return out

    # ── Diff ─────────────────────────────────────────────────────────────────

    def diffFiles(self, entry_a: dict, entry_b: dict) -> str:
        self._requireUnlocked()
        if (entry_a.get("size", 0) > DIFF_MAX_BYTES or
                entry_b.get("size", 0) > DIFF_MAX_BYTES):
            raise ValueError(
                f"File too large to diff in memory "
                f"(limit {DIFF_MAX_BYTES // 1024 // 1024} MB)."
            )
        text_a = self.viewFile(entry_a)
        text_b = self.viewFile(entry_b)
        diff   = list(difflib.unified_diff(
            text_a.splitlines(keepends=True),
            text_b.splitlines(keepends=True),
            fromfile=entry_a["name"],
            tofile=entry_b["name"],
            lineterm="",
        ))
        return "\n".join(diff) if diff else "(files are identical)"

    # ── History ──────────────────────────────────────────────────────────────

    def getHistory(self, limit: int = 50) -> List[dict]:
        return list(reversed(self._history[-limit:]))

    def verifyHistory(self) -> Tuple[bool, int]:
        self._requireUnlocked()
        return _verifyHistoryChain(bytes(self._mac_key), self._history)

    def _appendHistory(self, action: str, details: dict):
        if self._mac_key is None:
            return
        prev  = self._history[-1]["hmac"] if self._history else "GENESIS"
        entry = _makeHistoryEntry(bytes(self._mac_key), action, details, prev)
        self._history.append(entry)
        if len(self._history) > HISTORY_MAX_ENTRIES:
            self._history = self._history[-HISTORY_MAX_ENTRIES:]

    # ── Integrity check ──────────────────────────────────────────────────────

    def check(self) -> list:
        self._requireUnlocked()
        bad = []
        for entry in self._index:
            blob = self._blobs.get(entry["id"])
            if blob is None:
                bad.append(f"{entry['name']} (missing blob)"); continue
            try:
                decryptBuffer(blob, bytes(self._enc_key))
            except ValueError:
                bad.append(entry["name"])
        return bad

    # ── Info ─────────────────────────────────────────────────────────────────

    def info(self) -> dict:
        stat   = self.path.stat() if self.path and self.path.exists() else None
        cfg    = self._meta.get("argon2", ARGON2_CONFIG)
        mem_mb = cfg.get("memory_cost", 65536) // 1024
        all_tags = set()
        for e in self._index:
            all_tags.update(e.get("tags", []))
        compressed = sum(1 for e in self._index if e.get("compression", "none") != "none")
        return {
            "name":             self.name,
            "version":          FORMAT_VERSION,
            "file_count":       len(self._index),
            "total_size":       sum(e.get("size", 0) for e in self._index),
            "vault_size":       stat.st_size if stat else 0,
            "modified":         datetime.fromtimestamp(stat.st_mtime).strftime(
                                    "%Y-%m-%d %H:%M:%S") if stat else "—",
            "argon2_mem":       f"{mem_mb} MB",
            "argon2_time":      cfg.get("time_cost", 3),
            "argon2_threads":   cfg.get("parallelism", 4),
            "has_recovery":     "recovery_hmac" in self._meta,
            "frozen":           self._meta.get("frozen", False),
            "failed_attempts":  self._meta.get("failed_attempts", 0),
            "tag_count":        len(all_tags),
            "compressed_files": compressed,
            "history_entries":  len(self._history),
            "compression":      self._meta.get("compression", "none"),
            "description":      self._meta.get("description", ""),
        }

    def compact(self):
        self._requireUnlocked()
        self._appendHistory("COMPACT", {})
        self._flush()

    # ── Flush (atomic write) ─────────────────────────────────────────────────

    def _flush(self):
        enc_key = bytes(self._enc_key)
        mac_key = bytes(self._mac_key)

        meta_node    = dict(self._meta);  meta_node["_kvault_meta"]    = True
        history_node = {"_kvault_history": True, "entries": self._history}
        full_index   = [meta_node] + self._index + [history_node]

        sentinel  = encryptBuffer(SENTINEL_PLAIN, enc_key)
        idx_json  = json.dumps(full_index).encode("utf-8")
        enc_index = encryptBuffer(idx_json, enc_key)

        parts = [
            MAGIC, bytes([FORMAT_VERSION]), b"\x00\x00", self._salt,
            _pack_u32(len(sentinel)), sentinel,
            _pack_u32(len(enc_index)), enc_index,
        ]
        for entry in self._index:
            bid  = entry["id"]
            blob = self._blobs.get(bid)
            if blob is None: continue
            bid_b = bid.ljust(32).encode("ascii")[:32]
            parts += [bytes([FRAME_ADD]), bid_b, _pack_u32(len(blob)), blob]

        body = b"".join(parts)
        mac  = computeVaultHMAC(mac_key, body)
        tmp  = self.path.with_suffix(".kvault.tmp")
        tmp.write_bytes(body + mac)
        tmp.replace(self.path)

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _requireUnlocked(self):
        if self._locked or self._enc_key is None:
            raise PermissionError("Vault is locked")

    def findEntry(self, query: str) -> Optional[dict]:
        if query.isdigit():
            idx = int(query) - 1
            if 0 <= idx < len(self._index):
                return self._index[idx]
            return None
        q = query.lower()
        for e in self._index:
            if q in e["name"].lower():
                return e
        return None

    @property
    def is_locked(self) -> bool:
        return self._locked


# ─── MIME guesser ────────────────────────────────────────────────────────────

def _guessMime(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    return {
        ".pdf":  "PDF",
        ".txt":  "TXT", ".md": "TXT", ".rst": "TXT", ".log": "TXT",
        ".py":   "SRC", ".js": "SRC", ".ts":  "SRC", ".sh":  "SRC",
        ".html": "SRC", ".css":"SRC", ".java":"SRC", ".c":   "SRC",
        ".cpp":  "SRC", ".rs": "SRC", ".go":  "SRC",
        ".json": "DAT", ".csv":"DAT", ".xml": "DAT", ".yaml":"DAT",
        ".toml": "DAT", ".ini":"DAT", ".env": "DAT",
        ".pem":  "KEY", ".key":"KEY", ".crt": "KEY", ".pub": "KEY",
        ".jpg":  "IMG", ".jpeg":"IMG",".png": "IMG", ".gif": "IMG",
        ".webp": "IMG", ".bmp":"IMG", ".ico": "IMG", ".svg": "IMG",
        ".mp4":  "VID", ".mov":"VID", ".avi": "VID", ".mkv": "VID",
        ".mp3":  "AUD", ".wav":"AUD", ".flac":"AUD", ".aac": "AUD",
        ".zip":  "ZIP", ".tar":"ZIP", ".gz":  "ZIP", ".7z":  "ZIP",
        ".rar":  "ZIP",
    }.get(ext, "BIN")
