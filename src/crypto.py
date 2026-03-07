"""
KVAULT Crypto Layer
-------------------
encryptBuffer()    — AES-256-GCM → IV | AuthTag | Ciphertext
decryptBuffer()    — AES-256-GCM decrypt, raises ValueError on bad tag
deriveKey()        — Argon2id (with optional custom config)
deriveSubKeys()    — HMAC-SHA256 domain split → (encKey, macKey)
computeVaultHMAC() — HMAC-SHA256 over vault bytes
wipe()             — 3-pass zero-fill of a bytearray

Segfault fix (2026-03-07):
  Removed ctypes.memset(id(buf)+32, ...) from wipe(). Python's id() returns
  the object header address, not the data buffer address. Writing to that
  calculated offset corrupts the C heap and causes a segfault the next time
  any native C extension (OpenSSL/AES-GCM, Argon2) allocates memory.
  The pure-Python loop wipe is sufficient and safe.
"""

import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

from src.config import IV_BYTES, ARGON2_CONFIG, ENC_KEY_LABEL, MAC_KEY_LABEL


# ─── AES-256-GCM ─────────────────────────────────────────────────────────────

def encryptBuffer(plaintext: bytes, key: bytes) -> bytes:
    """Returns: IV(12) | AuthTag(16) | Ciphertext"""
    iv           = os.urandom(IV_BYTES)
    aesgcm       = AESGCM(key)
    ct_with_tag  = aesgcm.encrypt(iv, plaintext, None)
    auth_tag     = ct_with_tag[-16:]
    ciphertext   = ct_with_tag[:-16]
    return iv + auth_tag + ciphertext


def decryptBuffer(blob: bytes, key: bytes) -> bytes:
    """Decrypt IV|AuthTag|Ciphertext blob. Raises ValueError on auth failure."""
    if len(blob) < IV_BYTES + 16:
        raise ValueError("Blob too short")
    iv         = blob[:IV_BYTES]
    auth_tag   = blob[IV_BYTES:IV_BYTES + 16]
    ciphertext = blob[IV_BYTES + 16:]
    aesgcm     = AESGCM(key)
    try:
        return aesgcm.decrypt(iv, ciphertext + auth_tag, None)
    except Exception:
        raise ValueError("AES-GCM authentication failed — wrong key or tampered data")


# ─── Key Derivation ──────────────────────────────────────────────────────────

def deriveKey(password: str, salt: bytes, cfg: dict = None) -> bytes:
    """Derive 256-bit master key from password using Argon2id."""
    c = cfg if cfg else ARGON2_CONFIG
    return hash_secret_raw(
        secret      = password.encode("utf-8"),
        salt        = salt,
        time_cost   = c.get("time_cost",   ARGON2_CONFIG["time_cost"]),
        memory_cost = c.get("memory_cost", ARGON2_CONFIG["memory_cost"]),
        parallelism = c.get("parallelism", ARGON2_CONFIG["parallelism"]),
        hash_len    = c.get("hash_len",    ARGON2_CONFIG["hash_len"]),
        type        = Type.ID,
    )


def deriveSubKeys(master_key: bytes):
    """Split master key → (encKey, macKey) via HMAC-SHA256 domain labels."""
    enc_key = hmac.new(master_key, ENC_KEY_LABEL, hashlib.sha256).digest()
    mac_key = hmac.new(master_key, MAC_KEY_LABEL, hashlib.sha256).digest()
    return enc_key, mac_key


# ─── HMAC ────────────────────────────────────────────────────────────────────

def computeVaultHMAC(mac_key: bytes, data: bytes) -> bytes:
    return hmac.new(mac_key, data, hashlib.sha256).digest()


# ─── Memory Wipe ─────────────────────────────────────────────────────────────

def wipe(buf):
    """
    3-pass overwrite of a bytearray: 0x00 → 0xFF → 0x00.

    NOTE: We intentionally do NOT use ctypes.memset(id(buf)+32, ...) here.
    Python's id() returns the address of the Python object header, not the
    start of the buffer data. The data sits at a different offset depending
    on CPython internals. Writing to id(buf)+32 corrupts the C heap and
    causes a segfault the next time OpenSSL or Argon2 allocates memory.
    The pure-Python loop is safe, correct, and sufficient for our threat model.
    """
    if not isinstance(buf, (bytearray, memoryview)):
        return
    n = len(buf)
    for val in (0x00, 0xFF, 0x00):
        for i in range(n):
            buf[i] = val
