#!/usr/bin/env bash
# Put Tor, as a library for the iPhone app, in ios/vendor/tor-nolzma.xcframework.
#
#   scripts/fetch-tor-ios.sh
#
# An iPhone app can't start a separate tor program, so the app links C tor
# in. The Tor Project doesn't publish it built for iOS; this takes
# Tor.framework's prebuilt tor-nolzma.xcframework (tor, libevent, OpenSSL;
# used by Onion Browser) and refuses it unless its SHA-256 matches the one
# pinned below. Its builds are not reproducible, so the pin says "the file we
# checked", not "the file built from this source".
#
# Updating: set TOR_FRAMEWORK to the new release of
# https://github.com/iCepa/Tor.framework/releases, read its notes for the
# tor version, and pin the new zip's SHA-256.
set -euo pipefail

TOR_FRAMEWORK=v409.14.1 # tor 0.4.9.14, libevent 2.1.13, OpenSSL 3.6.5
SHA256=3582f1ebaeeff3e0b7178de6ff536c54b61ca1b598332affd6631e34ecbdf531

root=$(cd "$(dirname "$0")/.." && pwd)
dest="$root/ios/vendor"
if [ -f "$dest/tor-nolzma.xcframework/.version" ] &&
  [ "$(cat "$dest/tor-nolzma.xcframework/.version")" = "$TOR_FRAMEWORK" ]; then
  exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
file=tor-nolzma.xcframework.zip
echo "Downloading Tor for iPhone ($TOR_FRAMEWORK, about 60 MB)…"
curl -fsSL --proto '=https' --tlsv1.2 -o "$work/$file" \
  "https://github.com/iCepa/Tor.framework/releases/download/$TOR_FRAMEWORK/$file"
actual=$(shasum -a 256 "$work/$file" | cut -d' ' -f1)
if [ "$actual" != "$SHA256" ]; then
  echo "Tor download does not match its pinned SHA-256; refusing it." >&2
  exit 1
fi

unzip -q "$work/$file" -d "$work/unpacked"
mkdir -p "$dest"
rm -rf "$dest/tor-nolzma.xcframework"
mv "$work/unpacked/tor-nolzma.xcframework" "$dest/"
echo "$TOR_FRAMEWORK" >"$dest/tor-nolzma.xcframework/.version"
echo "Tor for iPhone is in ios/vendor/."
