# Patched dependencies

## nym-gateway-client 1.21.6

An unmodified copy of the crates.io release, plus one change so privmsg can
reach Nym gateways through Tor:

- `src/client/websockets.rs`: `set_socks5_proxy` / `Socks5Proxy`, and
  `connect_async_inner` connects through that SOCKS5 proxy when one is set
  (host name passed unresolved, so there is no local DNS lookup), with a
  numbered SOCKS user name per connection so each one gets its own Tor
  circuit.
- `src/lib.rs`: re-exports the two.
- `Cargo.toml`: adds `tokio-socks`.

Wired in with `[patch.crates-io]` in the root `Cargo.toml`. When moving Nym
to a new version, copy the new release here and re-apply the change
(search for "privmsg patch").

## proc_pidinfo 0.1.4

Nym's SQLite storage (`nym-sqlx-pool-guard`) uses it to wait until database
files are closed. As published it only builds for macOS: it calls
`proc_pidinfo`, `proc_pidfdinfo` and `proc_pidfileportinfo` through `libc`,
which declares them for macOS alone, although iOS's libSystem exports them
too. The copy here is unmodified except for a small `sys` module at the top
of `src/darwin.rs` that declares the three functions on iOS (search for
"privmsg patch").

## nym-statistics-common 1.21.6

Nym's usage-statistics reports, which privmsg turns off. It depends on
`sysinfo` 0.38 just to name the operating system in a report, and that
version of `sysinfo` doesn't build for iOS. The copy here is unmodified
except that on iOS it leaves `sysinfo` out (`Cargo.toml`) and takes the
name from the standard library instead (`src/report/client.rs`; search for
"privmsg patch").
