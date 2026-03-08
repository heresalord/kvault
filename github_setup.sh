#!/usr/bin/env sh
# KVAULT — GitHub repository setup script
# Run this from the root of your KVAULT project directory.
# Usage: sh github_setup.sh [your-github-username]
set -e

GITHUB_USER="${1:-heresalord}"
REPO_NAME="kvault"
REMOTE="https://github.com/${GITHUB_USER}/${REPO_NAME}.git"

GREEN='\033[0;32m'; BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'
info()    { printf "${BLUE}  →${RESET}  %s\n" "$1"; }
success() { printf "${GREEN}  ✓${RESET}  %s\n" "$1"; }

printf "\n${BOLD}🔐  KVAULT — GitHub setup${RESET}\n\n"

# 1. Ensure we're in a git repo
if [ ! -d ".git" ]; then
  info "Initialising git repository…"
  git init
  git checkout -b main 2>/dev/null || git branch -M main
fi

# 2. Copy installer scripts to repo root if they aren't there yet
for f in install.sh install.ps1; do
  if [ ! -f "$f" ]; then
    info "Note: $f not found in cwd — copy it from the outputs folder before pushing."
  fi
done

# 3. Create docs/ directory and remind about the Word doc
if [ ! -d "docs" ]; then
  mkdir -p docs
  info "Created docs/ — copy KVAULT_Command_Reference.docx into docs/ before pushing."
fi

# 4. Ensure a .gitignore exists
if [ ! -f ".gitignore" ]; then
  info "Writing .gitignore…"
  cat > .gitignore <<'EOF'
# Build outputs
target/
*.o
*.a
*.so
*.dylib
kvault
kvault.exe

# Python
__pycache__/
*.pyc
*.pyo
.venv/
dist/
build/
*.spec

# Vault files (never commit these!)
*.kvt
*.kvt.tmp
*.v1bak
*.v2bak

# Config
.kvault_config

# OS
.DS_Store
Thumbs.db
desktop.ini

# Editor
.idea/
.vscode/
*.swp
*.swo
EOF
  success ".gitignore created."
fi

# 5. Stage everything
info "Staging files…"
git add -A

# 6. Commit
COMMIT_MSG="Security hardening + .kvt extension: KVAULT v3.0.0

- AES-256-GCM encryption with per-blob random IV
- Argon2id key derivation (64 MB · 3 iterations · 4 threads)
- HMAC-SHA256 vault integrity — 4 tamper-detection layers
- Append-only log with automatic compaction
- Non-descriptive magic bytes (no tool fingerprint in file header)
- Vault files use .kvt extension (shorter, less identifiable)
- 3-pass wipe on temp files + vault delete (0x00->0xFF->0x00 + fsync)
- Clipboard opt-in via --clip flag (no silent clipboard writes)
- readline history disabled (no REPL commands written to disk)
- Windows, macOS, Linux support (Rust / C / Python)
- Persisted brute-force counter + FROZEN vault state
- Recovery phrase as second factor for FROZEN vaults
- Full REPL with fuzzy command suggestions
- One-line installers: install.sh + install.ps1"

if git diff --cached --quiet; then
  info "Nothing to commit — repository already up to date."
else
  git commit -m "$COMMIT_MSG"
  success "Committed."
fi

# 7. Add remote (skip if already set)
if git remote | grep -q "^origin$"; then
  info "Remote 'origin' already set: $(git remote get-url origin)"
else
  info "Adding remote origin: ${REMOTE}"
  git remote add origin "$REMOTE"
fi

# 8. Push
info "Pushing to ${REMOTE}…"
printf "\n${BOLD}  Next steps:${RESET}\n"
printf "  1. Create the repository on GitHub first:\n"
printf "     ${BOLD}https://github.com/new${RESET}  →  name: ${REPO_NAME}  →  do NOT init with README\n"
printf "  2. Then run:\n"
printf "     ${BOLD}git push -u origin main${RESET}\n"
printf "\n  Or if you have the GitHub CLI:\n"
printf "     ${BOLD}gh repo create ${GITHUB_USER}/${REPO_NAME} --public --source=. --push${RESET}\n\n"

printf "  One-liner install commands to add to your README:\n\n"
printf "  ${BOLD}macOS / Linux:${RESET}\n"
printf "    curl -fsSL https://raw.githubusercontent.com/${GITHUB_USER}/${REPO_NAME}/main/install.sh | sh\n\n"
printf "  ${BOLD}Windows (PowerShell):${RESET}\n"
printf "    irm https://raw.githubusercontent.com/${GITHUB_USER}/${REPO_NAME}/main/install.ps1 | iex\n\n"
