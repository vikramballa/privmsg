#!/usr/bin/env bash
# Put the official Tor program in <dest>/tor/, where privmsg looks for it.
#
#   scripts/fetch-tor.sh <dest> [platform]
#
# platform: macos-aarch64, macos-x86_64, linux-x86_64 or windows-x86_64
# (default: this machine). Downloads the Tor Expert Bundle from the Tor
# Project's archive and refuses it unless its SHA-256 matches the one pinned
# below. Only tor itself, its libraries and their licenses are kept; the
# pluggable transports (for bridges) are left out for now.
#
# Updating Tor: set TOR_VERSION to the new Tor Browser version, then take the
# four hashes from sha256sums-signed-build.txt in
# https://dist.torproject.org/torbrowser/<version>/ after checking that
# file's .asc signature against the Tor Browser Developers key
# EF6E 286D DA85 EA2A 4BA7 DE68 4E2C 6E87 9329 8290.
set -euo pipefail

TOR_VERSION=15.0.26
sha256_for() {
  case "$1" in
    macos-aarch64)  echo a3febb6179152b0b4f56a0f5cc57bf5cc8ecef7db35e7c3e9d5a044c8158c26c ;;
    macos-x86_64)   echo e1ae4d4a734d28bb590839188511deb3cebc26fcbce9df66d01b2c452060fe95 ;;
    linux-x86_64)   echo 19cf18726eecb362e0f21d27afa9ea9efe5da928bfdfbb1ceb5fe54519e87f4a ;;
    windows-x86_64) echo c1988c701de2f24f7d098d1d6d7f507b58f27740d097f29c246e0524d639b252 ;;
    *) return 1 ;;
  esac
}

dest=${1:?usage: fetch-tor.sh <dest> [platform]}
platform=${2:-}
if [ -z "$platform" ]; then
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) platform=macos-aarch64 ;;
    Darwin-x86_64) platform=macos-x86_64 ;;
    Linux-x86_64) platform=linux-x86_64 ;;
    MINGW*-x86_64 | MSYS*-x86_64 | CYGWIN*-x86_64) platform=windows-x86_64 ;;
    *) platform=unsupported ;;
  esac
fi
if ! expected=$(sha256_for "$platform"); then
  echo "No Tor download for this system. Install Tor yourself (for example" >&2
  echo "\`sudo apt install tor\`); privmsg finds it on your PATH." >&2
  exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
file="tor-expert-bundle-$platform-$TOR_VERSION.tar.gz"
curl -fsSL --proto '=https' --tlsv1.2 -o "$work/$file" \
  "https://archive.torproject.org/tor-package-archive/torbrowser/$TOR_VERSION/$file"

if command -v sha256sum >/dev/null; then
  actual=$(sha256sum "$work/$file" | cut -d' ' -f1)
else
  actual=$(shasum -a 256 "$work/$file" | cut -d' ' -f1)
fi
if [ "$actual" != "$expected" ]; then
  echo "Tor download does not match its pinned SHA-256; refusing it." >&2
  exit 1
fi

mkdir -p "$work/x"
tar -xzf "$work/$file" -C "$work/x"
rm -rf "$work/x/tor/pluggable_transports" "$work/x/tor/tor-gencert"*
mkdir -p "$work/x/tor/licenses"
for doc in tor libevent openssl zlib; do
  if [ -f "$work/x/docs/$doc.txt" ]; then
    cp "$work/x/docs/$doc.txt" "$work/x/tor/licenses/"
  fi
done
cat > "$work/x/tor/licenses/SOURCE.txt" <<SOURCE
This folder holds Tor from the Tor Expert Bundle $TOR_VERSION ($platform),
unmodified, as published by the Tor Project. privmsg runs it as a separate
program. Its licenses are in this folder; the source code for this build is
at https://archive.torproject.org/tor-package-archive/torbrowser/$TOR_VERSION/
and https://gitlab.torproject.org/tpo/applications/tor-browser-build.
SOURCE
# The bundle's macOS binaries are unsigned, and Apple silicon kills unsigned
# code on sight. An ad-hoc signature (what the Rust toolchain gives privmsg
# itself) is enough; the SHA-256 above already vouched for the contents.
case "$platform" in
  macos-*) codesign --force --sign - "$work/x/tor/tor" "$work/x/tor/"*.dylib ;;
esac
rm -rf "$dest/tor"
mkdir -p "$dest"
cp -R "$work/x/tor" "$dest/tor"
chmod -R u+rwX,go+rX "$dest/tor"
echo "Tor $TOR_VERSION ($platform) is in $dest/tor"
