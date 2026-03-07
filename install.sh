#!/usr/bin/env sh
# KVAULT installer — macOS & Linux
# Usage: curl -fsSL https://raw.githubusercontent.com/heresalord/kvault/main/install.sh | sh
set -e

REPO="https://github.com/heresalord/kvault"
BIN_DIR="${KVAULT_BIN_DIR:-/usr/local/bin}"
TMP=$(mktemp -d)

# ── Colours ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { printf "${BLUE}  →${RESET}  %s\n" "$1"; }
success() { printf "${GREEN}  ✓${RESET}  %s\n" "$1"; }
warn()    { printf "${YELLOW}  ⚠${RESET}  %s\n" "$1"; }
die()     { printf "${RED}  ✗${RESET}  %s\n" "$1" >&2; exit 1; }

# ── Banner ─────────────────────────────────────────────────────────────────
printf "\n${BOLD}🔐  KVAULT installer${RESET}\n"
printf "    AES-256-GCM · Argon2id · Zero-Knowledge\n\n"

# ── Detect OS & arch ───────────────────────────────────────────────────────
OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
  Darwin) PLATFORM="macos" ;;
  Linux)  PLATFORM="linux" ;;
  *)      die "Unsupported OS: $OS. Please build from source." ;;
esac

case "$ARCH" in
  x86_64 | amd64)          ARCH_TAG="x86_64" ;;
  aarch64 | arm64)          ARCH_TAG="aarch64" ;;
  *)                         die "Unsupported architecture: $ARCH. Please build from source." ;;
esac

info "Detected: ${OS} / ${ARCH}"

# ── Detect preferred implementation ───────────────────────────────────────
IMPL=""
if command -v cargo >/dev/null 2>&1; then
  IMPL="rust"
elif command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1; then
  IMPL="c"
elif command -v python3 >/dev/null 2>&1; then
  IMPL="python"
else
  die "No supported build toolchain found.\n  Install one of: Rust (https://rustup.rs), gcc/clang, or Python 3.10+"
fi

info "Using implementation: ${BOLD}${IMPL}${RESET}"

# ── Check for pre-built binary first ──────────────────────────────────────
# Try to download a pre-built release binary (fastest path)
TAG=$(curl -fsSL "https://api.github.com/repos/heresalord/kvault/releases/latest" \
       2>/dev/null | grep '"tag_name"' | cut -d'"' -f4) || true

BINARY_URL=""
if [ -n "$TAG" ]; then
  CANDIDATE="kvault-${PLATFORM}-${ARCH_TAG}"
  BINARY_URL="${REPO}/releases/download/${TAG}/${CANDIDATE}"
  info "Checking for pre-built binary: ${TAG}/${CANDIDATE}"

  HTTP_CODE=$(curl -fsSL -o "${TMP}/kvault" -w "%{http_code}" "$BINARY_URL" 2>/dev/null) || HTTP_CODE=0
  if [ "$HTTP_CODE" = "200" ]; then
    chmod +x "${TMP}/kvault"
    BUILT_FROM="pre-built binary (${TAG})"
  else
    warn "No pre-built binary found — building from source."
    BINARY_URL=""
  fi
fi

# ── Build from source if no binary ────────────────────────────────────────
if [ -z "$BINARY_URL" ]; then
  # Clone repo
  info "Cloning repository…"
  if command -v git >/dev/null 2>&1; then
    git clone --depth 1 "$REPO.git" "${TMP}/kvault-src" >/dev/null 2>&1 \
      || die "Failed to clone repository. Check your internet connection."
  else
    die "git not found. Install git and retry."
  fi

  SRC="${TMP}/kvault-src"

  case "$IMPL" in
    rust)
      info "Building with Cargo (this may take a minute on first build)…"
      cd "$SRC"
      cargo build --release --quiet \
        || die "Rust build failed. Run 'cargo build --release' in the repo for details."
      cp target/release/kvault "${TMP}/kvault"
      BUILT_FROM="Rust (cargo build --release)"
      ;;

    c)
      info "Building with make…"
      cd "$SRC"
      # Ensure libsodium is available
      if ! (pkg-config --exists libsodium 2>/dev/null || \
            [ -f /usr/include/sodium.h ] || [ -f /usr/local/include/sodium.h ]); then
        warn "libsodium not found. Attempting to install…"
        if command -v apt-get >/dev/null 2>&1; then
          sudo apt-get install -y libsodium-dev >/dev/null 2>&1 || die "Failed to install libsodium."
        elif command -v brew >/dev/null 2>&1; then
          brew install libsodium >/dev/null 2>&1 || die "Failed to install libsodium."
        elif command -v pacman >/dev/null 2>&1; then
          sudo pacman -S --noconfirm libsodium >/dev/null 2>&1 || die "Failed to install libsodium."
        elif command -v dnf >/dev/null 2>&1; then
          sudo dnf install -y libsodium-devel >/dev/null 2>&1 || die "Failed to install libsodium."
        else
          die "Please install libsodium manually and retry."
        fi
      fi
      make >/dev/null 2>&1 || die "C build failed. Run 'make' in the repo for details."
      cp kvault "${TMP}/kvault"
      BUILT_FROM="C (make)"
      ;;

    python)
      info "Setting up Python environment…"
      python3 -m pip install --quiet argon2-cffi cryptography \
        || die "pip install failed. Try: python3 -m pip install argon2-cffi cryptography"

      # Create a launcher wrapper
      KVAULT_PYTHON_DIR="${HOME}/.kvault"
      mkdir -p "$KVAULT_PYTHON_DIR"
      cp -r "${SRC}/." "$KVAULT_PYTHON_DIR/"

      # Write a thin shell wrapper as the "binary"
      cat > "${TMP}/kvault" <<'EOF'
#!/usr/bin/env sh
exec python3 "${HOME}/.kvault/kvault.py" "$@"
EOF
      chmod +x "${TMP}/kvault"
      BUILT_FROM="Python (kvault.py)"
      ;;
  esac
fi

# ── Install binary ─────────────────────────────────────────────────────────
info "Installing to ${BIN_DIR}…"

if [ -w "$BIN_DIR" ]; then
  cp "${TMP}/kvault" "${BIN_DIR}/kvault"
else
  sudo cp "${TMP}/kvault" "${BIN_DIR}/kvault" \
    || die "Could not install to ${BIN_DIR}. Try: KVAULT_BIN_DIR=~/.local/bin sh install.sh"
fi

chmod +x "${BIN_DIR}/kvault"

# ── Verify ─────────────────────────────────────────────────────────────────
if command -v kvault >/dev/null 2>&1; then
  success "kvault installed successfully!"
else
  # Not in PATH yet — check if BIN_DIR is in PATH
  if ! echo "$PATH" | grep -q "$BIN_DIR"; then
    warn "${BIN_DIR} is not in your PATH."
    printf "    Add this to your shell profile and restart your terminal:\n"
    printf "    ${BOLD}export PATH=\"${BIN_DIR}:\$PATH\"${RESET}\n"
  else
    success "kvault installed successfully!"
  fi
fi

# ── Cleanup ────────────────────────────────────────────────────────────────
rm -rf "$TMP"

# ── Summary ────────────────────────────────────────────────────────────────
printf "\n${BOLD}  Installation complete${RESET}\n"
printf "  Built from : %s\n" "$BUILT_FROM"
printf "  Installed  : ${BIN_DIR}/kvault\n"
printf "\n  Run ${BOLD}kvault${RESET} to get started.\n\n"
