# KVAULT installer — Windows (PowerShell)
# Usage: irm https://raw.githubusercontent.com/heresalord/kvault/main/install.ps1 | iex
#
# Requirements: PowerShell 5.1+ (Windows 10/11 built-in)
# Run as Administrator for system-wide install, or as a normal user for user-level install.

$ErrorActionPreference = 'Stop'

$REPO       = "https://github.com/heresalord/kvault"
$REPO_API   = "https://api.github.com/repos/heresalord/kvault"
$TMP        = [System.IO.Path]::GetTempPath() + [System.Guid]::NewGuid().ToString()
$IS_ADMIN   = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Install destination — system bin if admin, user bin otherwise
if ($IS_ADMIN) {
    $BIN_DIR = "C:\Program Files\kvault"
} else {
    $BIN_DIR = "$env:LOCALAPPDATA\kvault"
}

# ── Helpers ────────────────────────────────────────────────────────────────
function Info    ($msg) { Write-Host "  -> " -ForegroundColor Cyan   -NoNewline; Write-Host $msg }
function Success ($msg) { Write-Host "  v  " -ForegroundColor Green  -NoNewline; Write-Host $msg }
function Warn    ($msg) { Write-Host "  !  " -ForegroundColor Yellow -NoNewline; Write-Host $msg }
function Die     ($msg) { Write-Host "  X  " -ForegroundColor Red    -NoNewline; Write-Host $msg; exit 1 }

# ── Banner ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  KVAULT installer" -ForegroundColor White
Write-Host "  AES-256-GCM * Argon2id * Zero-Knowledge"
Write-Host ""

# ── Create temp directory ──────────────────────────────────────────────────
New-Item -ItemType Directory -Path $TMP | Out-Null

# ── Detect arch ───────────────────────────────────────────────────────────
$ARCH = if ([System.Environment]::Is64BitOperatingSystem) { "x86_64" } else { Die "32-bit Windows is not supported." }
Info "Detected: Windows / $ARCH"

# ── Try pre-built binary first ─────────────────────────────────────────────
$BINARY_INSTALLED = $false
$BUILT_FROM       = ""

try {
    $RELEASE = Invoke-RestMethod "$REPO_API/releases/latest" -ErrorAction SilentlyContinue
    $TAG     = $RELEASE.tag_name
    if ($TAG) {
        $ASSET_NAME = "kvault-windows-$ARCH.exe"
        $ASSET      = $RELEASE.assets | Where-Object { $_.name -eq $ASSET_NAME } | Select-Object -First 1
        if ($ASSET) {
            Info "Downloading pre-built binary: $TAG / $ASSET_NAME"
            Invoke-WebRequest -Uri $ASSET.browser_download_url -OutFile "$TMP\kvault.exe" -UseBasicParsing
            $BINARY_INSTALLED = $true
            $BUILT_FROM       = "pre-built binary ($TAG)"
            Success "Downloaded pre-built binary."
        } else {
            Warn "No pre-built Windows binary found for $TAG — building from source."
        }
    }
} catch {
    Warn "Could not reach GitHub API — building from source."
}

# ── Build from source if no binary ────────────────────────────────────────
if (-not $BINARY_INSTALLED) {

    # Detect available toolchain
    $HAS_CARGO  = $null -ne (Get-Command cargo  -ErrorAction SilentlyContinue)
    $HAS_PYTHON = $null -ne (Get-Command python  -ErrorAction SilentlyContinue) -or
                  $null -ne (Get-Command python3 -ErrorAction SilentlyContinue)

    if (-not $HAS_CARGO -and -not $HAS_PYTHON) {
        Write-Host ""
        Write-Host "  No supported build toolchain found." -ForegroundColor Red
        Write-Host "  Install one of:"
        Write-Host "    Rust   : https://rustup.rs  (recommended)"
        Write-Host "    Python : https://python.org/downloads  (3.10+)"
        Write-Host ""
        Die "Cannot proceed without a build toolchain."
    }

    # Clone repo
    $HAS_GIT = $null -ne (Get-Command git -ErrorAction SilentlyContinue)
    if (-not $HAS_GIT) { Die "git not found. Install Git for Windows: https://git-scm.com" }

    Info "Cloning repository..."
    git clone --depth 1 "$REPO.git" "$TMP\kvault-src" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Die "Failed to clone repository. Check your internet connection." }

    $SRC = "$TMP\kvault-src"

    if ($HAS_CARGO) {
        Info "Building with Cargo (first build may take a minute)..."
        Push-Location $SRC
        cargo build --release --quiet
        if ($LASTEXITCODE -ne 0) { Die "Rust build failed. Run 'cargo build --release' in the repo for details." }
        Pop-Location
        Copy-Item "$SRC\target\release\kvault.exe" "$TMP\kvault.exe"
        $BUILT_FROM = "Rust (cargo build --release)"

    } elseif ($HAS_PYTHON) {
        $PY = if (Get-Command python3 -ErrorAction SilentlyContinue) { "python3" } else { "python" }
        Info "Setting up Python environment..."

        & $PY -m pip install --quiet argon2-cffi cryptography windows-curses
        if ($LASTEXITCODE -ne 0) { Die "pip install failed. Try: $PY -m pip install argon2-cffi cryptography windows-curses" }

        $KVAULT_DIR = "$env:APPDATA\kvault"
        if (-not (Test-Path $KVAULT_DIR)) { New-Item -ItemType Directory -Path $KVAULT_DIR | Out-Null }
        Copy-Item "$SRC\*" $KVAULT_DIR -Recurse -Force

        # Write a thin CMD launcher
        @"
@echo off
$PY "$env:APPDATA\kvault\kvault.py" %*
"@ | Set-Content "$TMP\kvault.cmd"

        # Also create a .exe wrapper stub using PowerShell
        # The .cmd goes in BIN_DIR; we repurpose kvault.exe slot with .cmd
        $TMP_EXE = "$TMP\kvault.exe"
        Copy-Item "$TMP\kvault.cmd" $TMP_EXE  # will be renamed properly below
        $BUILT_FROM = "Python (kvault.py)"
    }
}

# ── Install ────────────────────────────────────────────────────────────────
Info "Installing to $BIN_DIR..."
if (-not (Test-Path $BIN_DIR)) { New-Item -ItemType Directory -Path $BIN_DIR | Out-Null }

if ($BUILT_FROM -match "Python") {
    # Install the CMD wrapper
    Copy-Item "$TMP\kvault.cmd" "$BIN_DIR\kvault.cmd" -Force
    # Also write kvault.bat as alias
    Copy-Item "$TMP\kvault.cmd" "$BIN_DIR\kvault.bat" -Force
} else {
    Copy-Item "$TMP\kvault.exe" "$BIN_DIR\kvault.exe" -Force
}

# ── Add to PATH if needed ─────────────────────────────────────────────────
$CURRENT_PATH = [System.Environment]::GetEnvironmentVariable("PATH", "User")
if ($CURRENT_PATH -notlike "*$BIN_DIR*") {
    Info "Adding $BIN_DIR to user PATH..."
    [System.Environment]::SetEnvironmentVariable(
        "PATH", "$BIN_DIR;$CURRENT_PATH", "User"
    )
    $env:PATH = "$BIN_DIR;$env:PATH"
    Warn "PATH updated. Open a new terminal for the change to take effect."
} else {
    Info "$BIN_DIR is already in PATH."
}

# ── Cleanup ────────────────────────────────────────────────────────────────
Remove-Item -Recurse -Force $TMP -ErrorAction SilentlyContinue

# ── Summary ────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Installation complete" -ForegroundColor Green
Write-Host "  Built from : $BUILT_FROM"
Write-Host "  Installed  : $BIN_DIR\kvault"
Write-Host ""
Write-Host "  Run kvault to get started."
Write-Host "  (Open a new terminal if PATH was just updated)"
Write-Host ""
