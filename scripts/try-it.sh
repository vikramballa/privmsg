#!/usr/bin/env bash
# Try privmsg in one step: creates two test users, Alice and Bob, connects
# them over the real Nym network, and opens a chat window for each.
#
#   ./scripts/try-it.sh
#
# Test users live in /tmp/privmsg-demo and use a fixed passphrase, so this
# is for trying privmsg out, not for real conversations.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
DEMO=${PRIVMSG_DEMO_DIR:-/tmp/privmsg-demo}
BIN="$ROOT/target/release/privmsg"
export PRIVMSG_PASSPHRASE=demo-passphrase
export RUST_LOG=error
LOG="$DEMO.log"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
trap 'say "Something went wrong. Details:"; cat "$LOG"; exit 1' ERR

if [ ! -x "$BIN" ] || [ -n "$(find crates -name '*.rs' -newer "$BIN" | head -1)" ]; then
  say "Building privmsg (the first time takes a few minutes)…"
  cargo build --release --locked
fi

say "1/4  Creating two test users: alice and bob"
rm -rf "$DEMO"
: > "$LOG"
"$BIN" --data-dir "$DEMO/alice" init >> "$LOG" 2>&1
"$BIN" --data-dir "$DEMO/bob" init >> "$LOG" 2>&1

say "2/4  Bob makes an invite for Alice (connecting to the Nym network, ~10 s)"
CODE=$("$BIN" --data-dir "$DEMO/bob" invite alice 2>> "$LOG")

say "3/4  Alice accepts Bob's invite (~10 s)"
"$BIN" --data-dir "$DEMO/alice" add bob "$CODE" >> "$LOG" 2>&1

say "4/4  Opening a chat window for each of them"
command_for() {
  echo "cd '$ROOT' && export PRIVMSG_PASSPHRASE=demo-passphrase && clear && '$BIN' --data-dir '$DEMO/$1' ui"
}
open_windows() {
  for user in bob alice; do
    osascript -e "tell application \"Terminal\" to do script \"$(command_for "$user")\"" || return 1
  done
  osascript -e 'tell application "Terminal" to activate'
}
# macOS may ask once whether this terminal may control Terminal: allow it.
if [ "$(uname)" = Darwin ] && [ -z "${PRIVMSG_DEMO_NO_WINDOWS:-}" ] && open_windows >> "$LOG" 2>&1; then
  WHERE="Two Terminal windows just opened, one for Bob and one for Alice."
else
  WHERE="Open two terminal windows and run one of these in each:
  $(command_for bob)
  $(command_for alice)"
fi

cat <<MSG

$WHERE

  • Wait about 10 seconds while they connect.
  • Bob's window will say "alice joined".
  • Type a message in either window and press Enter.
    It appears in the other window a few seconds later.
  • Press Esc in a window to close it.

Run ./scripts/try-it.sh again any time to start over with fresh users.
MSG
