# Architecture — metadata-private messenger

The goal, stated honestly: **unobservable communication within a large
anonymity set against a nation-state passive adversary.** Not "untraceable"
in the absolute sense — that's ruled out by the anonymity trilemma (you get
at most two of: strong anonymity, low latency, low bandwidth overhead) and
by the fundamental limits of the mix technique (your anonymity is never
better than the crowd you hide in). We build the strongest *achievable*
point and are explicit about the ceiling.

## The three layers

| Layer | Crate | Hides | Mechanism |
|------:|-------|-------|-----------|
| 1. Content | `privmsg-crypto` | *what* you say | MLS / RFC 9420 via OpenMLS (forward secrecy + post-compromise security, group-ready via TreeKEM) |
| 2. Transport | `privmsg-transport` | *who talks to whom*, your IP | Nym mixnet — fixed-size Sphinx packets, constant Poisson cover traffic, hop separation |
| 3. Identity | `privmsg-node` (`app`) + `Mux` | *persistent linkage* across conversations | SimpleX-style: no identifiers, one rotating mix address per conversation (§4) |

Each layer sees only its own job. The mixnet never sees plaintext; the
crypto layer never sees IPs. Keep it that way — a leak across layers (e.g.
a stable nickname riding inside the ciphertext, or a directory that maps an
overlay address to an IP) collapses the whole design.

## What is built
- **Layer 1** — MLS groups, identity snapshot/restore (OpenMLS 0.6 keeps all
  group state in its key store, so one snapshot carries every group), key
  package encoding with validation, group-id routing. A Welcome that reuses
  the id of a group we are already in is refused (it would overwrite that
  conversation).
- **Layer 2** — `Transport` (one endpoint = one mix address), `Network`
  (opens endpoints by *slot* name; `NymNetwork` keeps each slot's Nym keys in
  `slots/<id>/`), and `Mux` (several endpoints open at once, concurrent
  connect, every arrival tagged with its slot). Payloads are padded to 2 KiB
  blocks. `memory::MemoryNetwork` is an in-process stand-in with
  gateway-style offline queueing. Nym is behind the default `nym` feature so
  the fuzz targets build without it.
- **Node** — encrypted profile (`store`), wire formats (`wire`), messenger
  logic (`app`), decoy scheduler (`decoy`) as a library; CLI (`main`) and
  terminal UI (`tui`, ratatui) as the binary. Verified live on Nym mainnet:
  invites from one profile carrying different addresses and gateways,
  messages over both, offline delivery, and an address rotation followed by
  delivery to the new address.

### Wire format
```
transport frame = [u32 len][payload][zero pad to 2048·k]   (Sphinx-wrapped by Nym)
payload         = Envelope::Join { welcome, hello }          first contact
                | Envelope::Mls(mls_ciphertext)              afterwards
                | Envelope::Decoy(random bytes)              discarded
MLS plaintext   = Payload::Hello { reply_to, invite_tag }
                | Payload::Text(String)                      ≤ 16 KiB
                | Payload::Rotate { reply_to }               "write to me here now"
                | Payload::RotateAck                         sent to the new address
invite code     = "privmsg1:" base64url({ mix_address, key_package, tag })
```
Welcome and Hello travel in one frame because the mixnet reorders. Later
messages that still overtake the Join are buffered (bounded, and only on an
open invite's slot) until it arrives. All decoding of network input is
size-limited and rejects trailing bytes.

### Arrival checks
The node knows which slot each frame arrived on and enforces:
- a Join is considered only on the slot of an open invite (checked before any
  MLS work), and its tag must be that invite's;
- an MLS message is accepted only on its own conversation's current or
  retiring slot. Otherwise someone in conversation A could replay a frame
  to a suspected address B and learn from the reaction whether A and B
  belong to the same person.

### Profile at rest
`state.enc` = `"PRIVMSG2" | salt | nonce | XChaCha20-Poly1305(state)`, key =
Argon2id(passphrase, salt), header bound as AAD, atomic replace on every
save, exclusive file lock while open. State is saved after every change
because the MLS ratchet advances on every message. `"PRIVMSG1"` profiles are
upgraded on open: the single Nym client directory `nym/` is renamed to
`slots/legacy/` (idempotent if interrupted), every contact gets that slot
and `rotated_at = 0`, so they all move to their own addresses at the next
connection. The Nym SDK's own files under `slots/` are not covered. On
macOS the passphrase can be kept in the login keychain (`keychain save`).

### Build notes
- OpenMLS 0.6 contains `debug_assert!(false)` on AEAD failure, so a debug
  build would panic on one forged packet. The workspace disables debug
  assertions for `openmls`; the `handle_incoming` fuzz target is built with
  `-O` for the same reason.
- `nym-sdk` 1.21.6 accepts 1.22.x sub-crates that don't compile together;
  `Cargo.lock` pins the whole Nym tree to the 1.21.6 set. CI uses `--locked`.

## §4 — No-identifier handshake and per-conversation addresses (Layer 3)
Modelled on SimpleX:
- No accounts, no usernames, no persistent user IDs. The MLS credential is a
  random label; contact nicknames never leave the device.
- **One slot per conversation.** `invite` opens a fresh slot and puts its
  address in the code; `add` opens a fresh slot for the joiner's side. New
  Nym clients pick their gateway uniformly at random (SDK default), so two
  slots of one user don't share a gateway by design.
- **Rotation.** Each side rotates the address it *receives* on, so the two
  sides never conflict:
  ```
  A: open slot A2; state: current = A2, old = [A1 awaiting ack]; save
     MLS(Rotate{A2}) ─► B's address
  B: address for A := A2; MLS(RotateAck) ─► A2
  A: anything from B arriving on A2 ⇒ confirmed; A1 retires RETIRE_GRACE
     (24 h) later, once it has also been connected ≥ 60 s this session so
     its gateway has handed over anything stored
  ```
  The switch is saved before the Rotate is sent; an unconfirmed rotation is
  re-sent once per session by `Node::maintain`, which also rotates
  conversations whose address is older than `ROTATE_EVERY` (7 days).
  A migrated version 1 slot shared by several conversations is deleted only
  when the last one has moved off it.
- **Cost.** Every open slot is a full Nym client with its own cover traffic.
  `send` and `chat` (without decoys) connect only that contact's slots;
  `listen` and `ui` connect all of them, concurrently.
- **Residual.** All slots connect from the same IP. Each gateway sees that
  IP, so colluding gateways can link a user's slots. Running over a
  different network path per slot is out of scope.

## §5 — Decoy traffic (Phase 3)
Nym's cover traffic defeats a *global passive* observer at the packet level.
What remains visible is the rate of packets *arriving* at a recipient's
gateway: a burst means someone just wrote to them, and over long periods
the bursts can be correlated with a sender's activity.
- **What we do** (`decoy::Scheduler`, opt-in with `privmsg decoys on|<secs>`):
  while connected, every conversation sends on its own Poisson clock (mean
  interval configurable, default 10 s, minimum 2 s). Each tick carries the
  oldest queued real message, or an `Envelope::Decoy` padded to the same
  size. Sphinx encrypts the payload to the recipient, so only the recipient
  can tell a decoy from a message, and they drop it without touching MLS or
  the profile. Queued messages are flushed on exit; one-shot `send` is not
  delayed.
- **Placement:** in the node, beside `send_text`, not in Layer 2. A decoy
  needs the conversation's addresses, and Layers 1 and 2 stay unchanged.
- **The honest catch:** this is Loopix-style constant-rate sending, *not*
  Vuvuzela's differential privacy. There is no formal bound. Being online
  is still visible, latency rises by about one mean interval, and bandwidth
  grows with the number of conversations. A DP mechanism (calibrated noise
  on round participation) would need a round-based design that Nym doesn't
  provide.
- **Reference designs:** Vuvuzela (DP noise on metadata it can't encrypt),
  Loopix (Poisson mixing + cover, partly given by Nym), Stadium/Karaoke.

## Testing
- Unit and integration tests run whole conversations over `MemoryNetwork`:
  invites, wrong-address probes, rotation (including a lost Rotate and the
  old address still working in flight), retirement, decoys, removal, v1
  profile upgrade.
- `fuzz/` has cargo-fuzz targets for `unpad`, invite codes, every pre-auth
  decoder, and `Node::handle_incoming`. The last drives a real peer so that
  inputs reach past MLS: arbitrary authenticated plaintexts, corrupted real
  frames, and Joins with arbitrary Hellos.

## §6 — Cross-cutting hardening (not optional)
- **Anonymity set is a security property.** A perfect protocol with 5 users
  is traceable. Plan for the crowd from day one; treat adoption as security.
- **Endpoint security dominates.** A compromised device beats every layer.
- **No push notifications through Apple/Google** — they reintroduce identifiers.
- **Storage at rest:** one AEAD-sealed state file (above); the passphrase can
  live in the OS keychain (macOS).
- **Reproducible builds + pinned deps** so users can verify binary == source.
- **Accept asynchrony.** Every system in this tier is non-instant by design;
  naive "typing…"/read receipts re-leak timing.
