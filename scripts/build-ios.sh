#!/usr/bin/env bash
# Build the iPhone app's Rust core and open it in Xcode.
#
#   scripts/build-ios.sh            iPhone and simulator, with Tor
#   scripts/build-ios.sh --sim      simulator only (quicker), with Tor
#   scripts/build-ios.sh --no-tor   simulator only, without Tor linked in:
#                                   for trying the screens; turn Tor off in
#                                   the app's settings to connect at all
#   scripts/build-ios.sh --ipa      also make an unsigned privmsg.ipa for
#                                   SideStore / AltStore to sign and install
#
# Needs a Mac with Xcode, and Rust (the repository's rust-toolchain.toml
# picks the version). Steps:
#   1. Tor for iPhone (scripts/fetch-tor-ios.sh), unless --no-tor;
#   2. the Rust library (crates/mobile) for each target;
#   3. its Swift bindings, into ios/Privmsg/Generated/;
#   4. ios/build/PrivmsgCore.xcframework, which the Xcode project links;
#   5. ios/Local.xcconfig, once: a random bundle identifier for this copy of
#      the app, so the name Apple sees when you sign it says nothing.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

device=1 tor=1 ipa=0
for arg in "$@"; do
  case "$arg" in
    --sim) device=0 ;;
    --no-tor) device=0 tor=0 ;;
    --ipa) ipa=1 ;;
    *) echo "unknown option $arg (see the top of $0)" >&2; exit 1 ;;
  esac
done
if [ "$ipa" = 1 ] && [ "$device" = 0 ]; then
  echo "--ipa needs the iPhone build; leave out --sim / --no-tor." >&2
  exit 1
fi

targets=(aarch64-apple-ios-sim)
[ "$device" = 1 ] && targets+=(aarch64-apple-ios)
features=()
if [ "$tor" = 1 ]; then
  scripts/fetch-tor-ios.sh
  export PRIVMSG_TOR_XCFRAMEWORK="$root/ios/vendor/tor-nolzma.xcframework"
  features=(--features embedded-tor)
fi
rustup target add "${targets[@]}" >/dev/null

# The same minimum iOS as the app (ios/project.yml).
export IPHONEOS_DEPLOYMENT_TARGET=17.0
for target in "${targets[@]}"; do
  echo "Building the Rust core for ${target}…"
  cargo build -p privmsg-mobile --lib --release --locked --target "$target" ${features[@]+"${features[@]}"}
done

echo "Writing the Swift bindings…"
generated="$root/ios/Privmsg/Generated"
headers="$root/target/ios-headers"
rm -rf "$generated" "$headers"
mkdir -p "$generated" "$headers"
cargo run -q -p privmsg-mobile --features bindgen --bin uniffi-bindgen --locked -- \
  generate --library "target/${targets[0]}/release/libprivmsg_mobile.a" \
  --language swift --out-dir "$headers"
mv "$headers/privmsg_mobile.swift" "$generated/"
mv "$headers/privmsg_mobileFFI.modulemap" "$headers/module.modulemap"

echo "Packaging PrivmsgCore.xcframework…"
xcframework="$root/ios/build/PrivmsgCore.xcframework"
rm -rf "$xcframework"
args=()
for target in "${targets[@]}"; do
  args+=(-library "target/$target/release/libprivmsg_mobile.a" -headers "$headers")
done
xcodebuild -create-xcframework "${args[@]}" -output "$xcframework" >/dev/null

local_config="$root/ios/Local.xcconfig"
if [ ! -f "$local_config" ]; then
  id=p$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')
  cat >"$local_config" <<CONFIG
// This copy of the app's own settings (not shared, not in git).
// A random identifier, so the name Apple sees when you sign it says nothing.
PRODUCT_BUNDLE_IDENTIFIER = app.$id
// Your Apple developer team, if Xcode signs it (Signing & Capabilities sets it).
DEVELOPMENT_TEAM =
CONFIG
  echo "Made ios/Local.xcconfig (bundle identifier app.$id)."
fi

# Xcode writes the Team picked under Signing & Capabilities into the project
# file, which is in git. Keep it in Local.xcconfig instead; regenerating the
# project below then takes it out of the project file.
project="$root/ios/Privmsg.xcodeproj/project.pbxproj"
team=$(sed -n 's/.*DEVELOPMENT_TEAM = \([A-Z0-9][A-Z0-9]*\);.*/\1/p' "$project" 2>/dev/null | head -1)
if [ -n "$team" ] && grep -q '^DEVELOPMENT_TEAM = *$' "$local_config"; then
  sed -i '' "s/^DEVELOPMENT_TEAM = *$/DEVELOPMENT_TEAM = $team/" "$local_config"
  echo "Moved your signing team to ios/Local.xcconfig."
fi

if command -v xcodegen >/dev/null; then
  (cd ios && xcodegen generate --quiet)
elif [ -n "$team" ]; then
  echo "Note: your signing team is in ios/Privmsg.xcodeproj; don't commit that" >&2
  echo "change (brew install xcodegen, and this script moves it for you)." >&2
fi

if [ "$ipa" = 1 ]; then
  echo "Building the unsigned app…"
  out="$root/ios/build"
  xcodebuild -project ios/Privmsg.xcodeproj -scheme Privmsg -configuration Release \
    -sdk iphoneos -destination 'generic/platform=iOS' -derivedDataPath "$out/derived" \
    CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY= build >/dev/null
  rm -rf "$out/Payload" "$out/privmsg.ipa"
  mkdir -p "$out/Payload"
  cp -R "$out/derived/Build/Products/Release-iphoneos/Privmsg.app" "$out/Payload/"
  (cd "$out" && zip -qry privmsg.ipa Payload && rm -rf Payload)
  echo "Unsigned app: ios/build/privmsg.ipa (open it with SideStore or AltStore)."
fi

echo
echo "Done. Open ios/Privmsg.xcodeproj in Xcode, pick your iPhone or a"
echo "simulator at the top, and press Run (▶)."
