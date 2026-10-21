#!/usr/bin/env bash
# Build privmsg and install it, so you can open it by typing `privmsg`.
#
#   ./scripts/install.sh
#
# Installs to ~/.local/bin (override with PRIVMSG_INSTALL_DIR) and, if that
# folder isn't on your PATH yet, adds it to your shell's startup file.
set -euo pipefail
cd "$(dirname "$0")/.."
DEST=${PRIVMSG_INSTALL_DIR:-$HOME/.local/bin}

say() { printf '\033[1m%s\033[0m\n' "$*"; }

if ! command -v cargo >/dev/null; then
  say "privmsg is built with Rust, which isn't installed yet."
  echo "Install it from https://rustup.rs (one command), open a new terminal,"
  echo "then run ./scripts/install.sh again."
  exit 1
fi

say "Building privmsg (the first time takes a few minutes)…"
cargo build --release --locked -p privmsg-node

mkdir -p "$DEST"
cp target/release/privmsg "$DEST/privmsg"
say "Installed: $DEST/privmsg"

case ":$PATH:" in
  *":$DEST:"*) ready=1 ;;
  *) ready=0 ;;
esac
if [ "$ready" = 0 ]; then
  case "${SHELL:-}" in
    */zsh) rc="$HOME/.zshrc" ;;
    */bash) rc="$HOME/.bashrc" ;;
    *) rc="$HOME/.profile" ;;
  esac
  line="export PATH=\"$DEST:\$PATH\"  # added by privmsg's install.sh"
  grep -qsF "$line" "$rc" || printf '\n%s\n' "$line" >> "$rc"
  say "Added $DEST to your PATH in $rc. Open a new terminal window first."
fi

cat <<'MSG'

All set. To start privmsg, type:

    privmsg

The first time, it asks you to choose a password. Then:
  Ctrl-N  invite a friend (the invite is copied for you to send them)
  Ctrl-O  enter an invite code a friend sent you
  Esc     quit
MSG
