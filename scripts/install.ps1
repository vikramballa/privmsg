# Build privmsg on Windows and install it, so you can open it by typing
# `privmsg` in any new PowerShell or Terminal window.
#
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1
#
# Installs to %LOCALAPPDATA%\Programs\privmsg (override with
# PRIVMSG_INSTALL_DIR) and adds that folder to your user PATH.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$dest = if ($env:PRIVMSG_INSTALL_DIR) { $env:PRIVMSG_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\privmsg' }

function Say($text) { Write-Host $text -ForegroundColor Cyan }

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Say "privmsg is built with Rust, which isn't installed yet."
    Write-Host "Install it from https://rustup.rs (download rustup-init.exe and accept"
    Write-Host "the defaults, including the Visual Studio build tools it offers),"
    Write-Host "open a new PowerShell window, then run this script again."
    exit 1
}

Say "Building privmsg (the first time takes a few minutes)..."
cargo build --release --locked -p privmsg-node
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

New-Item -ItemType Directory -Force -Path $dest | Out-Null
Copy-Item 'target\release\privmsg.exe' (Join-Path $dest 'privmsg.exe') -Force
Say "Installed: $dest\privmsg.exe"

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$parts = if ($userPath) { $userPath -split ';' } else { @() }
if ($parts -notcontains $dest) {
    [Environment]::SetEnvironmentVariable('Path', (($parts + $dest) -join ';'), 'User')
    Say "Added $dest to your PATH. Open a new PowerShell window first."
}

Write-Host @'

All set. To start privmsg, type:

    privmsg

The first time, it asks you to choose a password. Then:
  Ctrl-N  invite a friend (the invite is copied for you to send them)
  Ctrl-O  enter an invite code a friend sent you
  Esc     quit
'@
