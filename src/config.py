"""
KVAULT Configuration Constants  —  Phase 3
"""

VERSION = "3.0.0"
FORMAT_VERSION = 0x03
MAGIC = b"KVLT"

# Argon2id parameters
ARGON2_CONFIG = {
    "time_cost":   3,
    "memory_cost": 65536,   # 64 MB
    "parallelism": 4,
    "hash_len":    32,
    "type":        "id",
}

# Crypto constants
IV_BYTES       = 12
AUTH_TAG_BYTES = 16
SALT_BYTES     = 32
HMAC_BYTES     = 32

# Auto-lock inactivity timeout (seconds)
AUTO_LOCK_SECONDS = 300  # 5 minutes

# Append-only log compaction threshold (fraction of dead bytes)
COMPACT_THRESHOLD = 0.25

# Frame types
FRAME_ADD    = 0x01
FRAME_REMOVE = 0x02
FRAME_RENAME = 0x03

# Sentinel plaintext for password verification
SENTINEL_PLAIN = b"KVAULT_OK_v3"

# HKDF labels
ENC_KEY_LABEL = b"KVAULT_ENC_KEY_v2"
MAC_KEY_LABEL = b"KVAULT_MAC_KEY_v2"

# Brute-force protection delays (seconds) — session-level
BRUTEFORCE_DELAYS = {
    1: 1, 2: 1,
    3: 3, 4: 3,
    5: 10, 6: 10, 7: 10, 8: 10, 9: 10,
}
BRUTEFORCE_LOCKOUT_THRESHOLD = 10
BRUTEFORCE_LOCKOUT_SECONDS   = 60

# Persisted attempt thresholds
PERSIST_WARN_THRESHOLD   = 5
PERSIST_DELAY_THRESHOLD  = 10
PERSIST_FROZEN_THRESHOLD = 20

# Vault + folder search dirs (relative to home)
VAULT_SEARCH_DIRS = [".", "Desktop", "Documents", "Downloads"]

# Fast folder search roots (relative to home, "" = home itself)
FOLDER_SEARCH_ROOTS = [
    "Desktop", "Documents", "Downloads",
    "Movies", "Music", "Pictures",
    "Projects", "Dev", "Sites", "",
]
FOLDER_SEARCH_MAX_DEPTH = 3

# Config file
CONFIG_FILENAME = ".kvault_config"

# Clipboard clear delay after view/cat (seconds). 0 = disabled.
CLIPBOARD_CLEAR_SECONDS = 30

# ── Phase 3 ──────────────────────────────────────────────────────────────────

# Compression: algorithm choices for add --compress
# Supported: "zstd", "zlib", "none"
DEFAULT_COMPRESSION = "none"

# Padding: round blob sizes up to nearest PADDING_BLOCK_SIZE bytes (0 = off)
# Hides exact file size from observers with hex access
PADDING_BLOCK_SIZE = 512   # bytes; 0 to disable

# History log: max entries kept in the encrypted tamper-evident log
HISTORY_MAX_ENTRIES = 500

# Glob expansion: enabled for add command
GLOB_ENABLED = True

# Diff: max file size to diff in memory (bytes)
DIFF_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
