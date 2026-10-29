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
- 🧅 **Tor built in**, so not even the Nym servers see your IP address.
- 💨 **Disappearing messages** that are deleted on both sides.
- 📶 **Light on data:** about 9 MB an hour in the default mode, and nothing
  at all while it's closed.
- 📱 **iPhone app (test version)** that talks to the desktop app, with Tor
  built in. See [iPhone](#iphone-test-version).

> ⚠️ **Status: prototype.** It works end to end on the live Nym network,
> but it has **not been independently security-audited**. Please don't
> rely on it for anything sensitive yet.

---

## Contents
- [What's new in v0.2.0](#whats-new-in-v020)
- [How it works](#how-it-works)
- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Where your data lives](#where-your-data-lives)
- [Privacy features](#privacy-features)
- [Internet data and Tor](#internet-data-and-tor)
- [What it protects (and what it doesn't)](#what-it-protects-and-what-it-doesnt)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [For developers](#for-developers)
- [License](#license)

---

## What's new in v0.2.0

- **Tor is built in and on by default.** The Nym servers no longer see your
  IP address. The download includes Tor; nothing extra to install.
- **Far less internet data.** The default `saver` mode uses about 9 MB an
  hour instead of hundreds, and each extra contact adds under 1 MB. One
  connection now sends for all your contacts (see
  [One sender, many quiet mailboxes](#one-sender-many-quiet-mailboxes)).
- **Faster messages.** Every short message now fits in a single network
  packet, so it typically arrives in about 3 seconds instead of 7.
- ### Disappearing messages

Press **Ctrl-D** in a chat. Both sides delete
  old messages.
- **Auto-sleep (optional).** `privmsg sleep 10` pauses the background
  traffic when you're not typing, to save even more data.

⚠️ **Everyone needs v0.2.0.** It can't exchange messages with v0.1.0, so
ask your contacts to update too. Your existing profile is upgraded
automatically, contacts and history included.

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
 │ 3. Tor                     │  hides your IP address from the
 │                            │  Nym servers (on by default)
 └────────────────────────────┘
     │
     ▼
 ┌────────────────────────────┐
 │ 4. Nym mixnet              │  layered encryption, several hops,
 │    (Sphinx packets +       │  random delays, constant fake traffic
 │     cover traffic)         │  → nobody sees both ends
 └────────────────────────────┘
     │
     ▼
 Your contact's device decrypts "hi"
```

Each layer only knows what it needs to: the mixnet never sees your message,
and the encryption layer never sees an IP address.

---

## Install

Works on **Mac**, **Linux** (including Parrot, Kali, Ubuntu, Debian) and
**Windows 10/11**, and as a test version on **iPhone**
([below](#iphone-test-version)).

### Easiest: the ready-made download (about 20 MB)

Go to the [Releases page](https://github.com/vikramballa/privmsg/releases)
and download the file for your computer. It contains privmsg and the Tor
program it uses to hide your IP address; keep the two together.

| Your computer | File to download |
|---|---|
| Mac with Apple chip (M1, M2, M3…) | `…-aarch64-apple-darwin.tar.gz` |
| Mac with Intel chip | `…-x86_64-apple-darwin.tar.gz` |
| Windows 10/11 | `…-x86_64-pc-windows-msvc.zip` |
| Linux (normal PC) | `…-x86_64-unknown-linux-gnu.tar.gz` |
| Linux on ARM (e.g. Raspberry Pi) | `…-aarch64-unknown-linux-gnu.tar.gz`, plus `sudo apt install tor` |

(Not sure which Mac? Apple menu → **About This Mac** → "Chip".)

**Mac:** double-click the download to unpack it, open **Terminal**, and
paste (use the folder name you got):

```bash
cd ~/Downloads/privmsg-v0.2.0-aarch64-apple-darwin
xattr -dr com.apple.quarantine .
./privmsg
```

The middle line tells macOS you trust this download, so it doesn't block
privmsg or Tor.

**Windows:** right-click the `.zip` → **Extract All**. Open the extracted
folder, click the address bar, type `powershell`, press Enter, then type
`.\privmsg.exe` and press Enter. If a blue "Windows protected your PC"
box appears, click **More info → Run anyway**.

**Linux:** `tar xzf privmsg-*.tar.gz`, `cd` into the folder, `./privmsg`.

Nothing else to install. Space used: about 20 MB for the download, about
45 MB unpacked, and under 1 MB for your messages.

### Build it yourself: Mac and Linux

This needs Rust, which takes a few GB of disk space while building. Most
people should use the download above.

On Linux, first install the build tools:
`sudo apt install -y build-essential git curl xclip` (Debian, Ubuntu, Parrot).

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

### Build it yourself: Windows

**1. Install Rust** (one time). Download `rustup-init.exe` from
[rustup.rs](https://rustup.rs), run it, and accept the defaults. When it
offers to install the Visual Studio build tools, say yes. Also install
[Git for Windows](https://git-scm.com/download/win).

**2. Download and install privmsg.** Open **PowerShell** (Start menu → type
"PowerShell") and run:

```powershell
git clone https://github.com/vikramballa/privmsg.git
cd privmsg
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

**3.** Open a **new** PowerShell window and type `privmsg`.

Use **Windows Terminal** (built into Windows 11; free in the Microsoft
Store for Windows 10) for the best-looking app. To paste an invite code
there, press **Ctrl-O** in privmsg and then **Ctrl-V** (or right-click).

Both install scripts also download Tor (checked against a pinned SHA-256)
and put it next to privmsg.

### iPhone (test version)

The same messenger as an iPhone app: it talks to the desktop version, and
Tor and the Nym mixnet run inside the app (no server). It isn't in the App
Store; you build it on a Mac with Xcode and install it on your own iPhone
with your Apple ID (free accounts re-install every 7 days):

```bash
scripts/build-ios.sh                     # first time: 10–20 minutes
open -a Xcode ios/Privmsg.xcodeproj      # pick your iPhone, press Run
```

Step-by-step instructions, what's different on a phone (no notifications;
connected only while the app is open) and its privacy settings are in
[ios/README.md](ios/README.md).

---

## Quick start

**1. Open privmsg:**

```bash
privmsg
```

The first time, it asks you to choose a password (at least 12 characters;
four random words work well).
It locks your messages on this computer, and it can't be recovered. On a
Mac it offers to remember the password in your Keychain so you don't have
to type it again.

**2. Invite a friend:** press **Ctrl-N**, type a name for them (only you
see it), and press **Enter**. Your invite code is shown and **copied to
your clipboard**. Paste it to your friend any way you like (WhatsApp,
Signal, email, a text). Each code works **once**. The code leaves your
clipboard after 3 minutes, or as soon as your friend joins (anything you
copied since is left alone). On a Mac it isn't sent to your other Apple
devices; on Windows it's kept out of Clipboard History and cloud sync.

**3. Your friend enters it:** in their privmsg they press **Ctrl-O**, paste
the code, press **Enter**, then type a name for you and press **Enter**.

**4. Chat:** your friend shows up in your contact list. Type a message
and press **Enter**.

| Key | What it does |
|---|---|
| **Ctrl-N** | Invite a friend |
| **Ctrl-O** | Enter an invite code someone sent you |
| **Ctrl-D** | Disappearing messages for this chat: off → 5 min → 1 hour → 1 day → 1 week |
| **↑ / ↓** | Switch between conversations |
| **Enter** | Send |
| **Esc** | Cancel, or quit |

💡 Your friend doesn't need to be online. Messages wait on the Nym network
and arrive the next time they open privmsg.

💡 The very first start takes up to a minute (Tor and Nym are setting up);
after that, starting takes about 15 seconds. Each message takes a few
seconds to arrive. That delay is part of what makes the traffic hard to
analyse.

💡 Whoever uses an invite first becomes that contact, so send codes in a
chat you trust. Once connected, type `/verify` and compare the safety
number with your friend in person or on a call: if it matches, nobody
intercepted the invite.

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
| `privmsg clear <name> [everyone]` | Delete every message with a contact, on your side only or on both sides |
| `privmsg unsend <name>` | Delete your last message to a contact, on both sides |
| `privmsg disappear <name> [off\|5m\|1h\|1d\|1w]` | Show or set disappearing messages with a contact (applies on both sides) |
| `privmsg verify <name>` | Show the safety number to compare with a contact |
| `privmsg rotate <name>` | Move a conversation to a new address now (it also happens weekly by itself) |
| `privmsg remove <name>` | Forget a contact or unused invite, with its addresses and keys |
| `privmsg address` | Show your mix address for each contact |
| `privmsg decoys [on\|off\|<seconds>]` | Show or set decoy traffic (see below) |
| `privmsg data [saver\|balanced\|maximum]` | Show or set how much internet data privmsg uses (see below) |
| `privmsg tor [on\|off]` | Show or set hiding your IP address with Tor (on by default) |
| `privmsg sleep [off\|<minutes>]` | Show or set auto-sleep: stop the cover traffic after that many minutes without typing (off by default, see below) |
| `privmsg keychain save` / `forget` | Keep the passphrase in the macOS keychain so privmsg stops asking, or remove it |
| `privmsg selftest` | Offline check of the encryption layer |

**Options and environment variables**

| | |
|---|---|
| `--data-dir <dir>` | Use a different profile folder (handy for running two profiles on one machine) |
| `PRIVMSG_HOME` | Default profile folder (otherwise `~/.privmsg`, or `%LOCALAPPDATA%\privmsg` on Windows) |
| `PRIVMSG_PASSPHRASE` | Supply the passphrase non-interactively, for scripts. ⚠️ Avoid on shared machines |
| `PRIVMSG_TOR` | Path to the `tor` program to use (otherwise `tor/` next to privmsg, then your PATH) |
| `RUST_LOG` | Log detail, e.g. `RUST_LOG=debug`. In the app, logs go to `privmsg.log` in the profile folder |

---

## Where your data lives

Everything is in your profile folder: `~/.privmsg` on Mac and Linux,
`%LOCALAPPDATA%\privmsg` on Windows (that is,
`C:\Users\<you>\AppData\Local\privmsg`, which Windows doesn't sync to
other PCs and OneDrive doesn't back up):

| File | Contents | Protected? |
|---|---|---|
| `state.enc` | Your keys, contacts, conversations, message history | ✅ Encrypted with your passphrase (Argon2id, 64 MiB × 3 passes, + XChaCha20-Poly1305) |
| `slots/` | One folder of Nym network keys per address (one per contact and per open invite, plus `sender`, which sends everything) | ⚠️ Not encrypted by privmsg, only by folder permissions: only your user account can open the profile folder (mode 0700 on Mac and Linux; on Windows an access list with your account as the only entry) |
| `tor/` | Tor's directory cache and entry guards, so later starts are quick | Folder permissions, like `slots/` |
| `lock` | Stops two copies of privmsg using the same profile | — |

🔑 **There is no password recovery.** If you forget your passphrase, your
profile can't be opened. That's by design.

Profiles made by older versions are upgraded automatically the first time
you open them. Your existing contacts then move to fresh addresses of their
own the next time you're connected. ⚠️ You and your contacts all need the
same version: messages from this version can't be read by older ones, and
the other way round.

---

## Privacy features

### One address per contact

Every invite you create, and every invite you
accept, gets its own Nym address (its own keys and a randomly chosen
gateway) and its own encryption identity, with its own key and a random
name tag. Two people you talk to can't compare notes and find out they're
talking to the same person. (Conversations started with v0.2.0 or earlier
keep the shared encryption identity they began with; remove and re-add a
contact to give it its own.)

### Weekly rotation

Each conversation's address is replaced every 7 days
while you're connected (or on demand with `privmsg rotate <name>`). Your
contact is told the new address inside the encrypted conversation and
confirms it; the old address keeps listening for a day after that, then its
keys are deleted.

### Decoys (optional)

`privmsg decoys on` makes each conversation send
something at random moments (every ~10 s on average) whenever you're in
`ui`, `chat` or `listen`. That's either a waiting message or a meaningless
decoy, so someone counting packets can't tell when you actually write.
The cost is bandwidth and a delay of a few seconds per message.
`privmsg decoys 30` picks a different average; `privmsg decoys off` turns
them off. A one-off `privmsg send` always goes out immediately.

### One sender, many quiet mailboxes

Your per-contact addresses only
*receive*. Everything you send goes out through one extra connection, the
*sender*, whose address is never given to anyone. Nym packets carry no
sender address, so your contacts still can't tell which connection wrote to
them. The sender runs the full fake-packet stream; each mailbox runs only a
slow trickle of fake packets, so its server can't simply count the messages
it receives. That's why extra contacts cost little data.

### Disappearing messages

Press **Ctrl-D** in a chat (or
`privmsg disappear <name> 1h`) to have messages deleted once they're older
than 5 minutes, 1 hour, 1 day or 1 week. Your contact's app is told and
deletes them too, and messages already older than that go at once. Deleted
messages are removed from the encrypted `state.enc`; a disk can keep old
copies of that file for a while, but they're still locked with your
passphrase.

### Deleting messages and chats

In the app, `/clear` empties the chat on your side and `/clear everyone`
on both sides (your contact sees that you cleared it). `/unsend` deletes
your last message on both sides. From the command line it's `privmsg clear
<name> [everyone]` and `privmsg unsend <name>`. On the iPhone, press and
hold a message, or use **⋯ → Delete chat**.

- You can delete only **your own** messages for everyone. A deleted
  message leaves no trace in the chat.
- "For everyone" is a request to your contact's app. If they already read
  it or took a screenshot, it's too late, and a modified app could ignore it.
- If their app stays closed for more than about a day, the request expires
  on the network, as a message would, and the message stays on their side.
- Your contact needs a version with deleting. Older versions ignore it.
- Messages from before this version can only be deleted on your side.

---

## Internet data and Tor

### Data modes

To hide when you're really chatting, privmsg keeps sending
fake packets while it's open, and your real messages blend into that
stream. How thick the stream is decides how much data privmsg uses:

| Mode | Data per hour open | A message takes | |
|---|---|---|---|
| `saver` (default) | about **9 MB**, plus under 1 MB per contact | ~3 seconds | good cover |
| `balanced` | about **32 MB**, plus about 2 MB per contact | ~2 seconds | more cover |
| `maximum` | about **860 MB**, plus about 18 MB per contact | instant | Nym's own default, built for a VPN |

Measured on the live Nym network (October 2026; `saver` with two contacts:
8.7–10.5 MB an hour). Tor carries all of it and adds its own overhead: in
the same test, the total going out to the internet was about twice
privmsg's own figure. Change the mode with `privmsg data balanced` (it
applies the next time privmsg connects). **When privmsg is closed it uses
no data at all.** Every mode keeps the fake-packet stream running, so
sending a message never makes a burst someone could spot; only the
stream's speed changes. Each message fits in one network packet, so it
leaves at the next tick of the stream.

### Auto-sleep (off by default)

`privmsg sleep 10` stops the fake-packet
stream after 10 minutes without typing; you still receive messages, and the
next key press starts it again (that takes a few seconds). While resting,
privmsg uses well under 1 MB an hour per contact. The catch: someone
watching your internet connection can then see *when* you're active, which
the always-on stream hides. `privmsg sleep off` turns it off again. It never
sleeps while decoys are on.

### Tor (on by default)

Without it, the first Nym server you connect to
can see your IP address (not your messages, and not who you talk to). With
Tor, privmsg reaches Nym through three Tor relays first, so the Nym servers
only see a Tor address, your internet provider only sees that you use Tor,
and each of your addresses goes through its own Tor circuit. No VPN needed.

It costs a slower first start (Tor connects in 10–30 seconds; later starts
are faster), roughly double the internet data (see above), and about 9 MB
of disk. If Tor can't start, privmsg refuses to connect rather than
quietly going without it. `privmsg tor off` turns it
off.

Where Tor itself is blocked (for example China, Iran or Russia), it needs
"bridges", which privmsg doesn't set up yet.

---

## What it protects (and what it doesn't)

**Protected ✅**
- **Message content:** end-to-end encrypted, with forward secrecy (each
  message key is deleted once used, so a later leak doesn't expose
  earlier messages).
- **Tampering:** forged, modified or replayed messages are rejected.
- **Who talks to whom:** hidden by the mixnet.
- **Your IP address:** the mixnet hides it from your contacts, and Tor hides
  it from the Nym servers.
- **Message length:** messages are padded to fixed-size blocks.
- **Identity:** no accounts or phone numbers. Contact nicknames never leave
  your device, and invite codes work only once.
- **Data on disk:** encrypted with your passphrase.
- **Linking your conversations:** each contact gets its own address and
  its own encryption keys, and addresses rotate weekly.
- **Someone intercepting an invite:** compare the safety number
  (`privmsg verify <name>`, or `/verify` in the app) with your contact.
- **When you write:** the sender's constant fake-packet stream hides it
  (unless you turn on auto-sleep); with decoys on, real messages are also
  hidden among decoys at your contact's end.
- **Old messages:** with disappearing messages on, both sides delete them.

**Not protected ⚠️**
- **Gateways working together (with Tor off):** all your addresses then
  connect from the same IP address, so gateway operators who pooled their
  logs could link them. With Tor on, each address arrives through its own
  Tor circuit instead.
- **Countries that block Tor:** Tor needs bridges there, which privmsg
  doesn't support yet. Use `privmsg tor off` (and ideally a VPN) meanwhile.
- **Long-term traffic analysis by a very powerful observer:** cover traffic
  and decoys help a lot, but there's no formal guarantee. Being online at
  all is still visible.
- **The `slots/` folder** isn't encrypted by privmsg.
- **Recovery after a key leak:** conversation keys are never refreshed
  after a conversation starts, so if someone copies your keys they can
  read new messages too until you remove the contact and connect again.
  (MLS can heal from this with regular key updates; privmsg doesn't do
  them yet.)
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
| Windows: `'privmsg' is not recognized` | Open a **new** PowerShell window after installing, so it picks up the updated PATH. |
| Windows: the invite wasn't copied | Select the code with the mouse and press **Ctrl-Shift-C** in Windows Terminal (or **Enter** in the old console window). |
| Messages are slow | Normal mixnet delay (a few seconds in `saver` mode). If nothing arrives, check your internet connection and that both sides are running a recent build. |
| `Tor was not found` | Keep the `tor` folder from the download next to privmsg, or install Tor (`brew install tor`, `sudo apt install tor`). |
| `Tor could not connect within 3 minutes` | Check your internet. If Tor is blocked where you are, use `privmsg tor off` for now. |
| Mac: `"tor" can't be opened` or privmsg is "killed" | Run `xattr -dr com.apple.quarantine .` inside the privmsg folder. |
| Linux: `GLIBC_2.39 not found` (or a similar version) | Your Linux is older than the system the download was built on. [Build it yourself](#build-it-yourself-mac-and-linux) instead; that always works. |
| Your contact never gets your messages | Check that you both run v0.2.0. Older versions can't read newer messages. |

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
  - [x] Prebuilt releases for macOS, Linux and Windows (GitHub Actions, on version tags)
  - [x] Native Windows support
- [x] **Phase 3: stronger metadata privacy**
  - [x] Decoy-traffic scheduler (Loopix-style constant-rate sending; no
        formal differential-privacy guarantee)
- [x] **Lighter and more private**
  - [x] Data modes: about 9 MB an hour by default instead of 860 per contact
  - [x] Tor in front of Nym, so the Nym servers never see your IP (bundled)
  - [ ] Tor bridges for countries that block Tor
  - [x] One sender for all contacts, receive-only mailboxes per contact
  - [x] One packet per message (faster delivery, less data)
  - [x] Disappearing messages (both sides), optional auto-sleep
  - [ ] "Lite" mode over Tor onion services only
- [ ] **Phones**
  - [x] iPhone app, test version (SwiftUI over the same Rust core, Tor built in)
  - [ ] Tried on more real iPhones
  - [ ] Android

Ideas and bug reports are welcome. Please open an issue.

---

## For developers

**Project layout**

```
crates/
  crypto/      Layer 1: MLS via OpenMLS (identities, groups, persistence)
  transport/   Layer 2: Nym clients (one sender + one mailbox per slot),
               multiplexer, padding, Tor (child process, or linked in on
               iPhone: feature `embedded-tor`), test network
  node/        The privmsg app: profile, wire format, invites, rotation,
               decoys (library), plus the CLI and terminal UI (binary)
  mobile/      The layer the phone app talks to: one `Messenger` object
               with Swift bindings (UniFFI), running node on its own thread
ios/           The iPhone app (SwiftUI; Xcode project from project.yml)
vendor/        Patched Nym crates: connect through Tor, and build for iOS
scripts/       install scripts; fetch-tor.sh (pinned, checksummed Tor);
               build-ios.sh and fetch-tor-ios.sh for the iPhone app
fuzz/          cargo-fuzz targets for everything read from the network
.github/workflows/  CI (fmt, clippy, tests) and release builds
```

**Build and test**

```bash
cargo test --workspace          # 84 tests, no network needed
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
publish macOS, Linux and Windows downloads, each with Tor, as a
pre-release.

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
