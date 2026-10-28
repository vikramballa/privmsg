# privmsg internal security review

**Version reviewed:** v0.2.0 (commit `698cced`) plus the fixes listed below
**Date:** 23 October 2026
**Reviewer:** Claude (AI assistant), the same assistant that wrote most of
the code.

> ⚠️ **This is not an independent audit.** It was done by the code's own
> author, who can share the code's blind spots. Treat it as a careful
> self-check. An independent audit by outside experts is still needed
> before privmsg is relied on for anything sensitive.

---

## Summary

| | |
|---|---|
| Findings | 15 (2 high, 6 medium, 7 low) |
| Fixed in this review | 10 |
| Open (documented, need bigger work) | 5 |
| Automated tests | 78, all passing (was 70), plus 1 opt-in clipboard test |
| Fuzzing | 4 targets × 25 min, ~73 million inputs, **no crashes** |
| Known-vulnerability scan | 18 advisories found, 2 fixed by updates, 1 mitigated in code, rest assessed below |
| Live test (Nym mainnet over Tor) | joins, messages in every direction, safety numbers, leak check: all passed |

The two high findings were both about privacy promises the code didn't
keep: contacts could link you through your encryption key, and the README
claimed a protection (post-compromise security) that privmsg doesn't
provide. The first is fixed; the second is corrected in the README and
listed as open work.

---

## What was checked

1. **Code reading**, every source file, with an attacker's view: the MLS
   layer (`crates/crypto`), the profile encryption (`store.rs`), the wire
   format and everything decoded from the network (`wire.rs`, `app.rs`),
   the transport and the new sender/mailbox design (`lib.rs`, `nym.rs`),
   Tor (`tor.rs` and the vendored gateway patch), local file permissions
   (`private_dir.rs`), the keychain, terminal output filtering, the
   Windows clipboard, the install scripts and both GitHub workflows.
2. **Dependencies**: `cargo deny check advisories` (RustSec database) and
   `cargo deny check sources` against all 828 locked crates.
3. **Fuzzing**: `unpad`, `invite_code`, `wire_decode`, `handle_incoming`
   (release mode, 25 minutes each).
4. **Tests**: full suite, plus new tests for each fix.
5. **Live**: three fresh profiles on the Nym mainnet over Tor; invites,
   joins, messages both ways, safety-number comparison, and a socket
   sampler (`lsof` every 0.5 s) to confirm every connection goes to the
   local Tor and nothing uses UDP/DNS.

---

## Findings

Severity: **High** = breaks a security or privacy promise; **Medium** =
weakens one under realistic conditions; **Low** = minor, or needs an
attacker who already has a lot of access.

| # | Severity | Finding | Status |
|---|---|---|---|
| H1 | High | One MLS signature key and credential for all contacts | ✅ Fixed |
| H2 | High | README claimed post-compromise security | ✅ Claim corrected; feature open |
| M1 | Medium | All gateway connections shared one Tor login | ✅ Fixed |
| M2 | Medium | Release workflow: unpinned actions, broad write access, no provenance | ✅ Fixed |
| M3 | Medium | No way to detect an intercepted invite | ✅ Fixed (safety numbers) |
| M4 | Medium | `tokio` 1.54.0 use-after-free in `Interval` | ✅ Fixed (1.54.1) |
| M5 | Medium | Vulnerable libraries inside the pinned Nym and MLS versions | ⚠️ Partly mitigated, open |
| M6 | Medium | Passphrase key derivation uses Argon2 defaults | ✅ Fixed (64 MiB × 3, stored in header) |
| L1 | Low | Low-order X25519 keys accepted in invites (hpke-rs) | ✅ Mitigated in code |
| L2 | Low | `ctutils` non-constant-time masks | ✅ Fixed (0.4.5) |
| L3 | Low | One unfiltered invisible direction character (U+061C) | ✅ Fixed |
| L4 | Low | All addresses connect and disconnect at the same moment | ⚠️ Open |
| L5 | Low | Mailboxes now have thinner cover than before v0.2.0 | ⚠️ Accepted trade-off |
| L6 | Low | Invite code stays on the clipboard (and macOS Universal Clipboard) | ✅ Fixed |
| L7 | Low | Debug logs (`RUST_LOG`) record contact names and addresses | ⚠️ Documented |

Robustness bugs found during live testing (not security, but fixed):
new addresses failed when Nym picked a gateway without a TLS listener,
and any connection gave up on one temporary Nym API error (HTTP 502).

### H1: one encryption identity for all contacts (fixed)

privmsg gives every contact a separate Nym address so contacts can't tell
they're talking to the same person. But every MLS key package and group
used the identity's single Ed25519 signature key and credential label.
Two contacts comparing their conversations, or anyone holding two of
your invite codes, would see the same key and link them.

**Fix** (`crates/crypto/src/lib.rs`): every key package and every group
we create now gets a fresh signature key and a random credential label,
kept in the identity's store. A session finds its own key through its
leaf in the group, so no new state is needed. Conversations made before
the fix keep working with the old key (tested); they become unlinkable
only after removing and re-adding the contact.
**Tests:** `invites_and_conversations_cannot_be_linked_by_key`,
`contacts_cannot_link_us_by_mls_key`,
`conversations_from_before_personas_still_work`.

### H2: post-compromise security was claimed but not provided (claim corrected)

MLS heals after a key compromise only when members regularly send
key-update commits. privmsg never commits after the first one, so if an
attacker copies your keys they can keep reading new messages.
**Fix:** README corrected ("Recovery after a key leak" under *Not
protected*). **Open:** add periodic self-updates. In a two-person group
both sides can commit at the same time, so this needs a rule for
resolving that (for example, the side with the lower leaf index wins).

### M1: Nym connections could share a Tor circuit (fixed)

Tor isolates circuits by destination and SOCKS login, and all gateway
connections used the same login. Two of your addresses (or the sender
and an address) on the same gateway would share a circuit, so the
gateway would see both arrive from one Tor exit at the same time.
**Fix** (`vendor/nym-gateway-client`): each connection uses a numbered
SOCKS user name, so each gets its own circuit.

### M2: release pipeline hardening (fixed)

Third-party actions were referenced by moving tags, so a hijacked tag
could have run code in the build. Every job had `contents: write`, and
downloads only had checksums, which prove integrity but not origin.
**Fix** (`.github/workflows/`): all actions pinned to commit SHAs;
`contents: read` everywhere except the publish job; the release build no
longer restores a cache; each download gets signed build provenance
(verify with `gh attestation verify <file> -R vikramballa/privmsg`).

### M3: no way to detect an intercepted invite (fixed)

Whoever uses an invite first becomes the contact. If an invite was
intercepted (say, the chat app it was sent through was compromised), the
attacker could sit in the middle, and nothing let users check.
**Fix:** a safety number derived from the MLS epoch authenticator, which
both sides share only if they're really in the same group:
`privmsg verify <name>` or `/verify` in the app. Live-tested: matching
numbers for each pair, different numbers across conversations.

### M4: tokio use-after-free (fixed)

RUSTSEC-2026-0384: `tokio::time::Interval` on the multi-threaded runtime
can use memory after it's freed. privmsg (maintenance timer) and Nym both
use it. **Fix:** `tokio` 1.54.0 → 1.54.1 (patch release, lockfile only).

### M5: vulnerable libraries pinned by Nym 1.21.6 and OpenMLS 0.6 (open)

These can't be updated without moving Nym or OpenMLS to new versions:

| Library | Advisory | Used for | Reachable in privmsg? |
|---|---|---|---|
| hpke-rs 0.2.0 | RUSTSEC-2026-0071 nonce reuse after 2³² seals | MLS | No: MLS uses one-shot HPKE |
| hpke-rs 0.2.0 | RUSTSEC-2026-0069 / -0070 | MLS | No: not used that way |
| hpke-rs-rust-crypto 0.2.0 | RUSTSEC-2026-0072 all-zero X25519 | MLS | Yes; mitigated (L1) |
| rustls 0.21.12, rustls-webpki 0.101.7, webpki-roots 0.24/0.25 | 7 certificate/TLS advisories | TLS to Nym gateways (tungstenite 0.20) | Partly. A misissued certificate could let a Tor exit see inside TLS, but Nym's own authenticated handshake and Sphinx encryption still protect the traffic |
| libcrux-kem 0.0.9 | RUSTSEC-2026-0330 / -0331 panics | Nym post-quantum crypto | Not on privmsg's code paths found; at worst a crash |
| h2 0.3.27 | RUSTSEC-2026-0258 | reqwest 0.11 (tendermint) | No: chain client not used |
| rsa 0.9.10 | RUSTSEC-2023-0071 Marvin | jwt-simple in nym-crypto | No: no RSA private-key use |
| bincode 1.3.3, derivative, paste, proc-macro-error2, rustls-pemfile, unsafe-libyaml | unmaintained | various (bincode also by privmsg) | No known vulnerability |

**Recommendation:** move to the current OpenMLS (with hpke-rs ≥ 0.6) and a
newer Nym release together, in a separate branch, with a profile
migration. Replace bincode in privmsg's own formats eventually.

### M6: Argon2 defaults for the passphrase (fixed)

`state.enc` is protected by Argon2id with the crate defaults (19 MiB,
2 passes), and passphrases need only 8 characters. Someone who copies
the file can try weak passphrases offline at a useful rate.
**Fix:** profile format `PRIVMSG5` stores the Argon2id cost in the header
(bound as associated data, so lowering it breaks decryption) and uses
64 MiB × 3 passes × 1 lane (RFC 9106's second recommendation; 0.14 s to
unlock on an M-series Mac). Older profiles are re-keyed with a fresh salt
the first time they're opened. Costs above 1 GiB / 64 passes / 16 lanes
are refused, so a tampered file can't hang the app. New passphrases need
12 characters, and setup suggests four random words. Tests:
`version_4_profile_is_rekeyed_at_the_current_cost`,
`passphrase_cost_is_bound_and_bounded`; also checked on a real version 4
profile (same conversations and safety number after the upgrade).

### L1: low-order keys in invites (mitigated)

hpke-rs 0.2 doesn't reject X25519 keys that make the shared secret all
zeros. A crafted invite could make us encrypt the Welcome under a key
anyone can compute. Only the invite's creator or someone who replaced
it could do this, and both are already in a position to read the
conversation, so the impact is small.
**Fix:** `decode_key_package` rejects key packages whose init or leaf key
is a low-order point (`contributory`, test `low_order_keys_are_refused`).

### L2–L3 (fixed)

`ctutils` 0.4.3 → 0.4.5 (RUSTSEC-2026-0385). `clean()` now also replaces
U+061C (Arabic letter mark), a direction-changing character.

### L4: addresses connect at the same moment (open)

All of a user's addresses (and the sender) connect when the app opens and
disconnect when it closes. Gateways can't see your IP (Tor), but
gateway operators who pooled their logs could match those moments and
guess that the addresses belong together.
**Recommendation:** spread the connections over a random minute or two
when the app opens (trade-off: slower start for some contacts).

### L5: thinner cover on mailboxes (accepted)

Since v0.2.0 a mailbox sends a loop packet about every 30 s instead of
being a full client, so its gateway sees fewer fake arrivals to hide
real ones in. This is the trade-off that cut data use by roughly half
with two contacts, and it's documented in the README.

### L6: invite code on the clipboard (fixed)

The invite is copied to the clipboard and left there. On a Mac with
Universal Clipboard it can reach your other Apple devices.
**Fix:** the code is taken off the clipboard after 3 minutes, when the
friend joins, or when the app closes, but only if it's still the code
(anything the user copied since is left alone). On a Mac it's copied
"this Mac only" (no Universal Clipboard) and marked concealed for
clipboard managers. Test: `invite_code_leaves_the_clipboard_but_other_text_stays`
(opt-in, as it uses the real clipboard; run on macOS).

### L7: debug logs (documented)

With `RUST_LOG` set, logs (`privmsg.log` in the app) contain contact
nicknames and, at debug level, Nym addresses, unencrypted. Off by default.

---

## Things checked and found sound

- Profile file: XChaCha20-Poly1305 with the header as associated data,
  random nonce per save, atomic replace, owner-only permissions, file lock.
- All network input is decoded with a size limit; frames are length-checked;
  messages are accepted only on the address that belongs to their
  conversation; joins only on an open invite with its secret tag.
- Early-message buffer is bounded (64), so strangers can't grow the profile
  without limit.
- Terminal output: control characters and direction overrides are replaced
  before anything from the network reaches the screen.
- Tor: ignores system torrc, listens on 127.0.0.1 only, host names resolved
  by Tor (no local DNS), refuses to connect without Tor, exits with
  privmsg. Live leak check: 643 samples, every socket to 127.0.0.1, no UDP.
- The sender's plain Nym messages carry no sender address or tag.
- Disappearing-message timers from a contact are range-checked.
- Install scripts and the release build verify Tor against pinned SHA-256s;
  all 828 Rust dependencies come from crates.io with checksums.

---

## Files changed in this review (not committed)

- `crates/crypto/src/lib.rs`: per-invite/per-group keys, safety number,
  low-order key check, tests
- `crates/crypto/Cargo.toml`, `Cargo.toml`: `x25519-dalek` (already in the tree)
- `crates/node/src/app.rs`: `safety_number`, tests
- `crates/node/src/main.rs`: `privmsg verify`, U+061C filtering, 12-character passphrases
- `crates/node/src/store.rs`: profile format 5 (stored, stronger Argon2 cost), re-keying, tests
- `crates/node/src/tui.rs`: `/verify`, clipboard clearing, this-Mac-only copy
- `crates/transport/src/nym.rs`: retry new addresses on another gateway,
  retry existing ones once
- `crates/transport/src/tor.rs`: comment
- `vendor/nym-gateway-client/src/client/websockets.rs`, `vendor/README.md`:
  per-connection Tor circuits
- `.github/workflows/ci.yml`, `release.yml`: pinned actions, least privilege,
  no release cache, build provenance
- `Cargo.lock`: tokio 1.54.1, ctutils 0.4.5, x25519-dalek dependency edge
- `README.md`: corrected claims, safety numbers
- `SECURITY-REVIEW.md`: this report
