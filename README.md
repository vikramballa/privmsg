# privmsg

**A private messenger that hides not just *what* you say, but *who* you talk to.**

Most "secure" messengers encrypt your messages but still reveal your
**metadata**: who you talk to, when, how often, and from which IP address.
That metadata alone is often enough to map someone's life. privmsg protects
both:

- 🔒 **Content** is end-to-end encrypted with **MLS** (RFC 9420, the IETF
  standard for secure group messaging).
- 🕵️ **Metadata** is hidden by sending every message through the
  **[Nym mixnet](https://nym.com)**: packets are bounced through several
  relays, shuffled, delayed, and mixed with fake "cover" traffic, so an
  observer watching the network can't tell who is talking to whom.
- 🙈 **No accounts.** No phone number, no email, no username. You connect
  with someone by swapping a one-time invite code.

> ⚠️ **Status: early prototype (Phase 1 of 3).** It works end to end on the
> live Nym network, but it has **not been security-audited**. Please don't
> rely on it for anything sensitive yet.

---

## Contents
- [How it works](#how-it-works)
- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Where your data lives](#where-your-data-lives)
- [What it protects (and what it doesn't)](#what-it-protects-and-what-it-doesnt)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [For developers](#for-developers)
- [License](#license)

---

## How it works

```
 You type "hi"
     │
     ▼
 ┌────────────────────────────┐
 │ 1. MLS encryption          │  only your contact can read it
 └────────────────────────────┘
     │
     ▼
 ┌────────────────────────────┐
 │ 2. Padding                 │  every message looks the same size
 └────────────────────────────┘
     │
     ▼
 ┌────────────────────────────┐
 │ 3. Nym mixnet              │  layered encryption, several hops,
 │    (Sphinx packets +       │  random delays, constant fake traffic
 │     cover traffic)         │  → nobody sees both ends
 └────────────────────────────┘
     │
     ▼
 Your contact's device decrypts "hi"
```

Each layer only knows what it needs to: the mixnet never sees your message,
and the encryption layer never sees an IP address. The full design is in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## Install

**You need:** macOS or Linux, and [Rust](https://rustup.rs) installed via
`rustup` (the right compiler version is picked automatically).

```bash
git clone https://github.com/<vikramballa >/privmsg.git
cd privmsg
cargo build --release
```

The first build takes a few minutes (it compiles the Nym networking
library). The program ends up at `./target/release/privmsg`. Optionally copy
it somewhere on your `PATH`:

```bash
cp target/release/privmsg ~/.local/bin/     # or /usr/local/bin
```

Check it works (no network needed):

```bash
privmsg selftest
# selftest OK: MLS content layer verified end to end (no network).
```

---

## Quick start

Two people, **Alice** and **Bob**, each on their own computer.

**1. Both create a profile** (you'll choose a passphrase; it encrypts
everything privmsg saves):

```bash
privmsg init
```

**2. Bob creates an invite for Alice:**

```bash
privmsg invite alice
# privmsg1:hjVoYkhNZ01vblNDQWRnaVVSeG82S2JnR0t...
```

Bob sends that code to Alice **over a channel he trusts**: in person, as a
QR code, or through another secure app. Each code works **once**.

**3. Alice accepts it**, choosing what she wants to call Bob:

```bash
privmsg add bob 'privmsg1:hjVoYkhNZ01vblNDQWRnaVVSeG82S2JnR0t...'
```

**4. Chat:**

```bash
privmsg chat bob        # Alice
privmsg chat alice      # Bob
```

Type a message and press Enter. Type `/quit` to leave.

💡 Your contact doesn't need to be online. Messages wait at their Nym gateway
and arrive the next time they connect.

💡 Connecting takes a few seconds, and each message takes a moment to
arrive. That small delay is part of what makes the traffic hard to analyse.

---

## Commands

| Command | What it does |
|---|---|
| `privmsg init` | Create a new encrypted profile |
| `privmsg invite <name>` | Make a one-time invite code; whoever uses it is saved as `<name>` |
| `privmsg add <name> <code>` | Accept someone's invite and save them as `<name>` |
| `privmsg chat <name>` | Interactive chat (`/quit` to leave) |
| `privmsg send <name> <message>` | Send a single message and exit |
| `privmsg listen [seconds]` | Just receive messages (Ctrl-C to stop) |
| `privmsg contacts` | List contacts and unused invites |
| `privmsg history <name>` | Show saved messages with a contact |
| `privmsg address` | Print your Nym mix address |
| `privmsg selftest` | Offline check of the encryption layer |

**Options and environment variables**

| | |
|---|---|
| `--data-dir <dir>` | Use a different profile folder (handy for running two profiles on one machine) |
| `PRIVMSG_HOME` | Default profile folder (otherwise `~/.privmsg`) |
| `PRIVMSG_PASSPHRASE` | Supply the passphrase non-interactively, for scripts. ⚠️ Avoid on shared machines |
| `RUST_LOG` | Log detail, e.g. `RUST_LOG=debug` |

---

## Where your data lives

Everything is in your profile folder (default `~/.privmsg`):

| File | Contents | Protected? |
|---|---|---|
| `state.enc` | Your keys, contacts, conversations, message history | ✅ Encrypted with your passphrase (Argon2id + XChaCha20-Poly1305) |
| `nym/` | Your Nym network keys and gateway registration | ⚠️ Not encrypted by privmsg (only by folder permissions) |
| `lock` | Stops two copies of privmsg using the same profile | — |

🔑 **There is no password recovery.** If you forget your passphrase, your
profile can't be opened. That's by design.

---

## What it protects (and what it doesn't)

**Protected ✅**
- **Message content:** end-to-end encrypted, with forward secrecy (old
  messages stay safe if keys leak later) and post-compromise security.
- **Tampering:** forged, modified or replayed messages are rejected.
- **Who talks to whom, and your IP address:** hidden by the mixnet.
- **Message length:** messages are padded to fixed-size blocks.
- **Identity:** no accounts or phone numbers. Contact nicknames never leave
  your device, and invite codes work only once.
- **Data on disk:** encrypted with your passphrase.

**Not protected yet ⚠️**
- **One address per profile:** every invite you create contains the same
  mix address, so people holding two of your invites can tell they came from
  the same person. *(Fix planned: Phase 2.)*
- **Long-term traffic analysis by a very powerful observer:** cover traffic
  helps a lot, but there's no formal guarantee yet. *(Phase 3.)*
- **The `nym/` folder** isn't encrypted by privmsg.
- **A hacked device:** if someone controls your computer, no messenger can
  protect you.
- **Small user base:** a mixnet hides you in a crowd, so the more people use
  it, the stronger it gets.

---

## Troubleshooting

| Message | Meaning / fix |
|---|---|
| `Not enough bandwidth. Trying to get more bandwidth…` | Normal Nym start-up notice. Wait a few seconds. |
| `profile … is in use by another privmsg process` | Another privmsg (e.g. a `chat` or `listen`) is running with the same profile. Close it first. |
| `wrong passphrase, or the profile is corrupted` | Check your passphrase. |
| `no profile in … (run privmsg init first)` | Create a profile, or point `--data-dir` at the right folder. |
| `refused a join that does not match any open invite` | Someone used an invite that was already used or never existed. Make a fresh invite. |
| Messages are slow | Normal mixnet delay. If nothing arrives, check your internet connection and that both sides are running a recent build. |

---

## Roadmap

- [x] **Phase 1: working messenger**
  - [x] MLS end-to-end encryption
  - [x] Nym mixnet transport with cover traffic and padding
  - [x] One-time invite codes, no accounts
  - [x] Encrypted local profile, message history
  - [x] Offline delivery
- [ ] **Hardening**
  - [ ] Fuzz testing of all network input
  - [ ] Independent security review
  - [ ] Optional passphrase storage in the OS keychain
- [ ] **Phase 2: unlinkable conversations**
  - [ ] Separate mix address per contact
  - [ ] Automatic address rotation
- [ ] **Usability**
  - [ ] Full-screen terminal UI (contact list, unread counts)
  - [ ] QR-code invites
  - [ ] Prebuilt releases for macOS and Linux
- [ ] **Phase 3: stronger metadata privacy**
  - [ ] Decoy-traffic scheduler, following the Vuvuzela/Loopix research

Ideas and bug reports are welcome. Please open an issue.

---

## For developers

**Project layout**

```
crates/
  crypto/      Layer 1: MLS via OpenMLS (identities, groups, persistence)
  transport/   Layer 2: Nym mixnet client, padding, in-memory test network
  node/        The privmsg app: encrypted profile, wire format, invites, CLI
docs/
  ARCHITECTURE.md   Design, wire format, threat model, future plug-in points
```

**Build and test**

```bash
cargo test --workspace          # 38 tests, no network needed
cargo clippy --workspace --all-targets
cargo fmt --all
```

The Rust version is pinned in `rust-toolchain.toml` so everyone builds with
the same compiler.

**Try two profiles on one machine**

```bash
privmsg --data-dir /tmp/alice init
privmsg --data-dir /tmp/bob   init
privmsg --data-dir /tmp/bob   invite alice           # copy the code
privmsg --data-dir /tmp/alice add bob '<code>'
privmsg --data-dir /tmp/bob   listen                 # in one terminal
privmsg --data-dir /tmp/alice send bob "hello"       # in another
```

⚠️ **Don't run a plain `cargo update`.** The Nym library's published crates
only compile together at matching versions, and `Cargo.lock` pins that
working set. See the note in `Cargo.toml`.

**Further reading**
- OpenMLS: https://docs.rs/openmls · RFC 9420
- Nym Rust SDK: https://nym.com/docs/developers/rust
- Vuvuzela: https://pdos.csail.mit.edu/projects/vuvuzela.html
- Loopix: "The Loopix Anonymity System" (USENIX Security 2017)
- SimpleX: pairwise queue identifiers (model for Phase 2)
- Anonymity trilemma: IEEE S&P 2018 (the theoretical limits)

---

## License

Not chosen yet. Until a license is added, all rights are reserved by the
author.
