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

# Tor, which privmsg uses to hide your IP address. Same pinned version and
# SHA-256 as scripts/fetch-tor.sh (update both together).
$torVersion = '15.0.26'
$torSha256 = 'c1988c701de2f24f7d098d1d6d7f507b58f27740d097f29c246e0524d639b252'
Say "Downloading Tor..."
$work = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $file = Join-Path $work 'tor.tar.gz'
    Invoke-WebRequest -UseBasicParsing -OutFile $file `
        "https://archive.torproject.org/tor-package-archive/torbrowser/$torVersion/tor-expert-bundle-windows-x86_64-$torVersion.tar.gz"
    if ((Get-FileHash $file -Algorithm SHA256).Hash -ne $torSha256) {
        throw 'Tor download does not match its pinned SHA-256; refusing it.'
    }
    tar -xzf $file -C $work
    if ($LASTEXITCODE -ne 0) { throw 'could not unpack Tor' }
    Remove-Item -Recurse -Force (Join-Path $work 'tor\pluggable_transports'), (Join-Path $work 'tor\tor-gencert.exe')
    $torDest = Join-Path $dest 'tor'
    if (Test-Path $torDest) { Remove-Item -Recurse -Force $torDest }
    Copy-Item -Recurse (Join-Path $work 'tor') $torDest
    Say "Installed: $torDest\tor.exe"
} finally {
    Remove-Item -Recurse -Force $work
}

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
