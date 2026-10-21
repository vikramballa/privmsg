# Architecture — metadata-private messenger (Phase 1 + future plug-in points)

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
| 3. Identity | *(Phase 2 — see §4)* | *persistent linkage* across conversations | SimpleX-style no-identifier, per-contact ephemeral addresses |

Each layer sees only its own job. The mixnet never sees plaintext; the
crypto layer never sees IPs. Keep it that way — a leak across layers (e.g.
a stable nickname riding inside the ciphertext, or a directory that maps an
overlay address to an IP) collapses the whole design.

## What is DONE in Phase 1
- **Layer 1** — MLS groups, identity snapshot/restore (OpenMLS 0.6 keeps all
  group state in its key store, so one snapshot carries every group), key
  package encoding with validation, group-id routing.
- **Layer 2** — `Transport` trait; `NymTransport` over `nym-sdk` 1.21.6 with
  on-disk client keys (stable address), send-queue flush on exit, and
  padding of every payload to 2 KiB blocks. `memory::MemoryNetwork` is an
  in-process stand-in (with gateway-style offline queueing) for tests.
- **Node** — encrypted profile (`store`), wire formats (`wire`), messenger
  logic (`app`), CLI (`main`). Verified live: two profiles exchanging
  messages over Nym mainnet, including delivery to an offline recipient.

### Wire format
```
transport frame = [u32 len][payload][zero pad to 2048·k]   (Sphinx-wrapped by Nym)
payload         = Envelope::Join { welcome, hello }          first contact
                | Envelope::Mls(mls_ciphertext)              afterwards
MLS plaintext   = Payload::Hello { reply_to, invite_tag }
                | Payload::Text(String)
invite code     = "privmsg1:" base64url({ mix_address, key_package, tag })
```
Welcome and Hello travel in one frame because the mixnet reorders. Later
messages that still overtake the Join are buffered (bounded) until it
arrives. All decoding of network input is size-limited and rejects trailing
bytes.

### Profile at rest
`state.enc` = `"PRIVMSG1" | salt | nonce | XChaCha20-Poly1305(state)`, key =
Argon2id(passphrase, salt), header bound as AAD, atomic replace on every
save, exclusive file lock while open. State is saved after every change
because the MLS ratchet advances on every message. The Nym SDK's own files
in `nym/` are not covered.

### Build notes
- OpenMLS 0.6 contains `debug_assert!(false)` on AEAD failure, so a debug
  build would panic on one forged packet. The workspace disables debug
  assertions for `openmls` in every profile.
- `nym-sdk` 1.21.6 accepts 1.22.x sub-crates that don't compile together;
  `Cargo.lock` pins the whole Nym tree to the 1.21.6 set.

## §4 — Plug-in point: the no-identifier handshake (Layer 3)
This is what stops two of your conversations from being linkable even by the
servers. Model it on SimpleX:
- No accounts, no usernames, no random user IDs anywhere persistent.
- Each contact gets its own **pairwise, ephemeral queue/overlay address**.
  Rotate them; never reuse one across contacts.
- Bootstrap a contact via a **one-time invite link** exchanged out of band.
  *(Done in Phase 1: `privmsg invite` codes are single-use.)*
- **Attach point in code:** the `MixAddress` in `privmsg-transport` is today
  one stable Sphinx address per node. Phase 2 replaces it with a *set* of
  per-contact addresses minted at handshake time, plus a rotation schedule.
  The crypto layer's local `name` labels (see `Identity::new`) must never be
  promoted to network identifiers.

## §5 — Plug-in point: differential-privacy noise (nation-state tier)
Nym's cover traffic defeats a *global passive* observer at the packet level.
To reach the Vuvuzela/Loopix tier — provable metadata privacy even when the
adversary can watch and statistically analyze whole rounds — add
**differentially private noise** to the residual, un-encryptable metadata
(e.g. per-round decoy conversations, calibrated noise on observable counts).
- **Reference designs to lift from:** Vuvuzela (DP noise on metadata it
  can't encrypt), Loopix (Poisson mixing + cover already partly given by Nym),
  Stadium/Karaoke (horizontal scaling of the same idea).
- **Attach point in code:** a noise/decoy scheduler sitting beside
  `Transport::send` — emitting calibrated dummy conversations on the same
  Sphinx stream so real round-participation is hidden. Keep it in Layer 2;
  Layers 1 and 3 don't change.
- **The honest catch (document it for users):** like Vuvuzela, expect a
  small irreducible leak (e.g. counts of idle vs. active users) and a
  latency cost. State your threat model and the residual explicitly.

## §6 — Cross-cutting hardening (not optional)
- **Anonymity set is a security property.** A perfect protocol with 5 users
  is traceable. Plan for the crowd from day one; treat adoption as security.
- **Endpoint security dominates.** A compromised device beats every layer.
- **No push notifications through Apple/Google** — they reintroduce identifiers.
- **Storage at rest:** SQLCipher; keys in the OS keystore.
- **Reproducible builds + pinned deps** so users can verify binary == source.
- **Accept asynchrony.** Every system in this tier is non-instant by design;
  naive "typing…"/read receipts re-leak timing.
