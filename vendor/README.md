# Patched dependencies

## nym-gateway-client 1.21.6

An unmodified copy of the crates.io release, plus one change so privmsg can
reach Nym gateways through Tor:

- `src/client/websockets.rs`: `set_socks5_proxy` / `Socks5Proxy`, and
  `connect_async_inner` connects through that SOCKS5 proxy when one is set
  (host name passed unresolved, so there is no local DNS lookup).
- `src/lib.rs`: re-exports the two.
- `Cargo.toml`: adds `tokio-socks`.

Wired in with `[patch.crates-io]` in the root `Cargo.toml`. When moving Nym
to a new version, copy the new release here and re-apply the change
(search for "privmsg patch").
