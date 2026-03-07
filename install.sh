#!/usr/bin/env bash
# ┌─────────────────────────────────────────────────────────────────┐
# │  KVAULT — One-line installer for macOS and Linux               │
# │  Usage: curl -fsSL https://raw.githubusercontent.com/          │
# │         KMSStudio/kvault/main/install.sh | bash                │
# └─────────────────────────────────────────────────────────────────┘

set -e

REPO="https://github.com/KMSStudio/kvault.git"
INSTALL_DIR="$HOME/.kvault"
BIN="/usr/local/bin/kvault"
BIN_FALLBACK="$HOME/.local/bin/kvault"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "  ${CYAN}·${RESET}  $*"; }
success() { echo -e "  ${GREEN}✓${RESET}  $*"; }
warn()    { echo -e "  ${YELLOW}⚠${RESET}  $*"; }
error()   { echo -e "  ${RED}✗${RESET}  $*"; exit 1; }

echo ""
echo -e "${BOLD}  🔐 KVAULT Installer${RESET}"
echo "  ─────────────────────────────────────"
echo ""

# ── 1. Check Python ────────────────────────────────────────────────────────
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" -c "import sys; print(sys.version_info >= (3,10))" 2>/dev/null)
        if [ "$ver" = "True" ]; then PYTHON="$cmd"; break; fi
    fi
done
[ -z "$PYTHON" ] && error "Python 3.10+ is required. Install from https://python.org"
success "Python found: $($PYTHON --version)"

# ── 2. Check git ───────────────────────────────────────────────────────────
command -v git &>/dev/null || error "git is required. Install with: brew install git  or  apt install git"

# ── 3. Clone or update ────────────────────────────────────────────────────
if [ -d "$INSTALL_DIR/.git" ]; then
    info "Updating existing install at $INSTALL_DIR …"
    git -C "$INSTALL_DIR" pull --ff-only --quiet
    success "Updated to latest version."
else
    info "Cloning KVAULT into $INSTALL_DIR …"
    git clone --depth 1 --quiet "$REPO" "$INSTALL_DIR"
    success "Cloned."
fi

# ── 4. Install Python dependencies ────────────────────────────────────────
info "Installing Python dependencies …"
"$PYTHON" -m pip install --quiet --upgrade pip
"$PYTHON" -m pip install --quiet -r "$INSTALL_DIR/requirements.txt"
success "Dependencies installed."

# ── 5. Write launcher script ───────────────────────────────────────────────
LAUNCHER="#!/usr/bin/env bash
exec \"$PYTHON\" \"$INSTALL_DIR/kvault.py\" \"\$@\"
"

write_launcher() {
    local target="$1"
    mkdir -p "$(dirname "$target")"
    printf '%s' "$LAUNCHER" > "$target"
    chmod +x "$target"
}

if [ -w "$(dirname "$BIN")" ] || sudo -n true 2>/dev/null; then
    if [ -w "$(dirname "$BIN")" ]; then
        write_launcher "$BIN"
    else
        tmpf=$(mktemp)
        printf '%s' "$LAUNCHER" > "$tmpf"
        chmod +x "$tmpf"
        sudo mv "$tmpf" "$BIN"
        sudo chmod +x "$BIN"
    fi
    success "Installed: $BIN"
    INSTALLED_AT="$BIN"
else
    # Fallback: install to ~/.local/bin (no sudo needed)
    write_launcher "$BIN_FALLBACK"
    success "Installed: $BIN_FALLBACK  (no sudo — user-local)"
    INSTALLED_AT="$BIN_FALLBACK"
    # Check if ~/.local/bin is on PATH
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *)
            warn "Add this to your shell profile to make 'kvault' available everywhere:"
            echo ""
            echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
            echo ""
            # Auto-add to common shell profiles
            for profile in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
                if [ -f "$profile" ] && ! grep -q '\.local/bin' "$profile" 2>/dev/null; then
                    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$profile"
                    info "Added PATH update to $profile"
                fi
            done
            ;;
    esac
fi

# ── 6. Verify ─────────────────────────────────────────────────────────────
echo ""
echo "  ─────────────────────────────────────"
echo -e "${BOLD}  Installation complete!${RESET}"
echo ""
echo "  Launch KVAULT from any terminal:"
echo ""
echo -e "    ${CYAN}kvault${RESET}"
echo ""
echo "  Or if the command isn't found yet:"
echo ""
echo -e "    ${CYAN}$INSTALLED_AT${RESET}"
echo ""
