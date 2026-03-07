# ┌─────────────────────────────────────────────────────────────────┐
# │  KVAULT — One-line installer for Windows (PowerShell)          │
# │  Usage: irm https://raw.githubusercontent.com/                 │
# │         KMSStudio/kvault/main/install.ps1 | iex                │
# └─────────────────────────────────────────────────────────────────┘

$ErrorActionPreference = "Stop"

$REPO        = "https://github.com/KMSStudio/kvault.git"
$INSTALL_DIR = Join-Path $env:USERPROFILE ".kvault"
$SCRIPTS_DIR = Join-Path $env:USERPROFILE "AppData\Local\Programs\kvault"

function info    ($msg) { Write-Host "  · " -ForegroundColor Cyan   -NoNewline; Write-Host $msg }
function success ($msg) { Write-Host "  ✓ " -ForegroundColor Green  -NoNewline; Write-Host $msg }
function warn    ($msg) { Write-Host "  ⚠ " -ForegroundColor Yellow -NoNewline; Write-Host $msg }
function fail    ($msg) { Write-Host "  ✗ " -ForegroundColor Red    -NoNewline; Write-Host $msg; exit 1 }

Write-Host ""
Write-Host "  🔐 KVAULT Installer" -ForegroundColor White
Write-Host "  ─────────────────────────────────────"
Write-Host ""

# ── 1. Check Python ───────────────────────────────────────────────────────
$PYTHON = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd -c "import sys; print(sys.version_info >= (3,10))" 2>$null
        if ($ver -eq "True") { $PYTHON = $cmd; break }
    } catch {}
}
if (-not $PYTHON) {
    fail "Python 3.10+ is required. Download from: https://python.org/downloads/"
}
$pyver = & $PYTHON --version 2>&1
success "Python found: $pyver"

# ── 2. Check git ──────────────────────────────────────────────────────────
try { git --version | Out-Null } catch { fail "git is required. Download from: https://git-scm.com" }

# ── 3. Clone or update ────────────────────────────────────────────────────
if (Test-Path (Join-Path $INSTALL_DIR ".git")) {
    info "Updating existing install at $INSTALL_DIR ..."
    git -C $INSTALL_DIR pull --ff-only --quiet
    success "Updated to latest version."
} else {
    info "Cloning KVAULT into $INSTALL_DIR ..."
    git clone --depth 1 --quiet $REPO $INSTALL_DIR
    success "Cloned."
}

# ── 4. Install Python dependencies ────────────────────────────────────────
info "Installing Python dependencies ..."
& $PYTHON -m pip install --quiet --upgrade pip
& $PYTHON -m pip install --quiet -r (Join-Path $INSTALL_DIR "requirements.txt")
success "Dependencies installed."

# ── 5. Write launcher batch file ──────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $SCRIPTS_DIR | Out-Null
$launcherPath = Join-Path $SCRIPTS_DIR "kvault.cmd"
$launcherContent = "@echo off`r`n$PYTHON `"$INSTALL_DIR\kvault.py`" %*`r`n"
Set-Content -Path $launcherPath -Value $launcherContent -Encoding ASCII
success "Launcher written: $launcherPath"

# ── 6. Add to PATH ────────────────────────────────────────────────────────
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath -notlike "*$SCRIPTS_DIR*") {
    [Environment]::SetEnvironmentVariable("PATH", "$userPath;$SCRIPTS_DIR", "User")
    $env:PATH += ";$SCRIPTS_DIR"
    success "Added to PATH (User scope). Restart your terminal to pick up the change."
} else {
    info "$SCRIPTS_DIR already in PATH."
}

# ── 7. Done ───────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ─────────────────────────────────────"
Write-Host "  Installation complete!" -ForegroundColor White
Write-Host ""
Write-Host "  Launch KVAULT from any terminal:"
Write-Host ""
Write-Host "    kvault" -ForegroundColor Cyan
Write-Host ""
Write-Host "  (If 'kvault' isn't found yet, restart your terminal first.)"
Write-Host ""
