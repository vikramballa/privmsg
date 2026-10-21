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
- 🧩 **A different address for every contact**, replaced every week, so
  your conversations can't be linked to each other by address.

> ⚠️ **Status: prototype.** It works end to end on the live Nym network,
> but it has **not been independently security-audited**. Please don't
> rely on it for anything sensitive yet.

---

## Contents
- [How it works](#how-it-works)
- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Where your data lives](#where-your-data-lives)
- [Addresses, rotation and decoys](#addresses-rotation-and-decoys)
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

You need a Mac or a Linux computer.

**1. Install Rust** (one time). Open Terminal and run the command shown at
[rustup.rs](https://rustup.rs), then open a new Terminal window.

**2. Download and install privmsg:**

```bash
git clone https://github.com/vikramballa/privmsg.git
cd privmsg
./scripts/install.sh
```

The first build takes a few minutes. After that you can open privmsg from
any Terminal window by typing `privmsg`.

*(Ready-made downloads will appear on the
[Releases page](https://github.com/vikramballa/privmsg/releases) once a
version is published.)*

---

## Quick start

**1. Open privmsg:**

```bash
privmsg
```

The first time, it asks you to choose a password (at least 8 characters).
It locks your messages on this computer, and it can't be recovered. On a
Mac it offers to remember the password in your Keychain so you don't have
to type it again.

**2. Invite a friend:** press **Ctrl-N**, type a name for them (only you
see it), and press **Enter**. Your invite code is shown and **copied to
your clipboard**. Paste it to your friend any way you like (WhatsApp,
Signal, email, a text). Each code works **once**.

**3. Your friend enters it:** in their privmsg they press **Ctrl-O**, paste
the code, press **Enter**, then type a name for you and press **Enter**.

**4. Chat:** your friend shows up in your contact list. Type a message
and press **Enter**.

| Key | What it does |
|---|---|
| **Ctrl-N** | Invite a friend |
| **Ctrl-O** | Enter an invite code someone sent you |
| **↑ / ↓** | Switch between conversations |
| **Enter** | Send |
| **Esc** | Cancel, or quit |

💡 Your friend doesn't need to be online. Messages wait on the Nym network
and arrive the next time they open privmsg.

💡 Connecting takes about 10 seconds, and each message takes a few seconds
to arrive. That delay is part of what makes the traffic hard to analyse.

💡 Whoever uses an invite first becomes that contact, so send codes in a
chat you trust. Once connected, check it's really your friend.

**Just want to see it work?** `./scripts/try-it.sh` creates two test
users on your computer, connects them, and opens a chat window for each.

---

## Commands

| Command | What it does |
|---|---|
| `privmsg` | Open the app (sets it up the first time) |
| `privmsg init` | Create a new encrypted profile without opening the app |
| `privmsg invite <name> [--qr]` | Make a one-time invite code (optionally as a QR code); whoever uses it is saved as `<name>` |
| `privmsg add <name> <code>` | Accept someone's invite and save them as `<name>` |
| `privmsg ui` | Same as plain `privmsg` |
| `privmsg chat <name>` | Line-by-line chat (`/quit` to leave) |
| `privmsg send <name> <message>` | Send a single message and exit (up to 16 KiB) |
| `privmsg listen [seconds]` | Just receive messages (Ctrl-C to stop) |
| `privmsg contacts` | List contacts, unread counts and unused invites |
| `privmsg history <name>` | Show saved messages with a contact |
| `privmsg rotate <name>` | Move a conversation to a new address now (it also happens weekly by itself) |
| `privmsg remove <name>` | Forget a contact or unused invite, with its addresses and keys |
| `privmsg address` | Show your mix address for each contact |
| `privmsg decoys [on\|off\|<seconds>]` | Show or set decoy traffic (see below) |
| `privmsg keychain save` / `forget` | Keep the passphrase in the macOS keychain so privmsg stops asking, or remove it |
| `privmsg selftest` | Offline check of the encryption layer |

**Options and environment variables**

| | |
|---|---|
| `--data-dir <dir>` | Use a different profile folder (handy for running two profiles on one machine) |
| `PRIVMSG_HOME` | Default profile folder (otherwise `~/.privmsg`) |
| `PRIVMSG_PASSPHRASE` | Supply the passphrase non-interactively, for scripts. ⚠️ Avoid on shared machines |
| `RUST_LOG` | Log detail, e.g. `RUST_LOG=debug`. In the app, logs go to `privmsg.log` in the profile folder |

---

## Where your data lives

Everything is in your profile folder (default `~/.privmsg`):

| File | Contents | Protected? |
|---|---|---|
| `state.enc` | Your keys, contacts, conversations, message history | ✅ Encrypted with your passphrase (Argon2id + XChaCha20-Poly1305) |
| `slots/` | One folder of Nym network keys per address (one per contact and per open invite) | ⚠️ Not encrypted by privmsg (only by folder permissions) |
| `lock` | Stops two copies of privmsg using the same profile | — |

🔑 **There is no password recovery.** If you forget your passphrase, your
profile can't be opened. That's by design.

Profiles made by older versions are upgraded automatically the first time
you open them. Your existing contacts then move to fresh addresses of their
own the next time you're connected (both sides need the new version).

---

## Addresses, rotation and decoys

**One address per contact.** Every invite you create, and every invite you
accept, gets its own Nym address (its own keys and a randomly chosen
gateway). Two people you talk to can't compare notes and find out they're
talking to the same person.

**Weekly rotation.** Each conversation's address is replaced every 7 days
while you're connected (or on demand with `privmsg rotate <name>`). Your
contact is told the new address inside the encrypted conversation and
confirms it; the old address keeps listening for a day after that, then its
keys are deleted.

**Decoys (optional).** `privmsg decoys on` makes each conversation send
something at random moments (every ~10 s on average) whenever you're in
`ui`, `chat` or `listen`. That's either a waiting message or a meaningless
decoy, so someone counting packets can't tell when you actually write.
The cost is bandwidth and a delay of a few seconds per message.
`privmsg decoys 30` picks a different average; `privmsg decoys off` turns
them off. A one-off `privmsg send` always goes out immediately.

Each address is a separate Nym client with its own cover traffic, so many
contacts means more background traffic. That's expected.

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

- **Linking your conversations:** each contact gets its own address, and
  addresses rotate weekly.
- **When you write:** with decoys on, real messages are hidden among decoys.

**Not protected ⚠️**
- **Gateways working together:** all your addresses connect from the same
  IP address. Each gateway sees your IP, so gateway operators who pooled
  their logs could link your addresses.
- **Long-term traffic analysis by a very powerful observer:** cover traffic
  and decoys help a lot, but there's no formal guarantee. Being online at
  all is still visible.
- **The `slots/` folder** isn't encrypted by privmsg.
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
| `… has not confirmed the last address change yet` | Your contact hasn't been online since your last rotation. It completes by itself; try `rotate` again later. |
| `message is … bytes; the limit is 16384` | Split long text into several messages. |
| Asked for a passphrase although you used `keychain save` | The keychain entry is tied to the profile folder's path. Run `keychain save` again for that folder. |
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
  - [x] Fuzz testing of all network input (`fuzz/`)
  - [x] Internal security review pass
  - [ ] Independent security audit
  - [x] Optional passphrase storage in the OS keychain (macOS)
- [x] **Phase 2: unlinkable conversations**
  - [x] Separate mix address per contact
  - [x] Automatic address rotation
- [x] **Usability**
  - [x] Full-screen terminal UI (contact list, unread counts)
  - [x] QR-code invites
  - [x] Prebuilt releases for macOS and Linux (GitHub Actions, on version tags)
- [x] **Phase 3: stronger metadata privacy**
  - [x] Decoy-traffic scheduler (Loopix-style constant-rate sending; no
        formal differential-privacy guarantee)

Ideas and bug reports are welcome. Please open an issue.

---

## For developers

**Project layout**

```
crates/
  crypto/      Layer 1: MLS via OpenMLS (identities, groups, persistence)
  transport/   Layer 2: Nym clients per slot, multiplexer, padding, test network
  node/        The privmsg app: profile, wire format, invites, rotation,
               decoys (library), plus the CLI and terminal UI (binary)
fuzz/          cargo-fuzz targets for everything read from the network
docs/
  ARCHITECTURE.md   Design, wire format, threat model
.github/workflows/  CI (fmt, clippy, tests) and release builds
```

**Build and test**

```bash
cargo test --workspace          # 60 tests, no network needed
cargo clippy --workspace --all-targets
cargo fmt --all
```

**Fuzzing** (needs nightly and `cargo install cargo-fuzz`):

```bash
cd fuzz
cargo +nightly fuzz run unpad           # also: invite_code, wire_decode
cargo +nightly fuzz run -O handle_incoming
```

`-O` matters for `handle_incoming`. Without it, debug assertions are on,
and OpenMLS hits a `debug_assert!(false)` on every failed decryption, which
is exactly what that fuzzer produces. The targets build without the `nym`
feature, so they don't compile the Nym tree at all.

**Releases:** pushing a tag like `v0.2.0` makes GitHub Actions build and
publish macOS and Linux binaries as a pre-release.

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

Licensed under the [Apache License, Version 2.0](LICENSE).
