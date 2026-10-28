# privmsg for iPhone

The same messenger as the desktop app, on your iPhone. It talks to the
desktop version (0.2), and like it, has no account and no server: Tor and
the Nym mixnet run inside the app.

**Status: first version, for testing.** In the iPhone simulator, with its
built-in Tor, it connects to the desktop app over the real network and
messages go both ways. It builds for a real iPhone but has not been tried
on one yet.

## What you need

- A Mac with **Xcode** (free, from the App Store) and **Rust**
  (<https://rustup.rs>).
- An **Apple ID** to install the app on your own iPhone. A free one works;
  the app then has to be re-installed every 7 days. Tip: a separate Apple ID
  just for this keeps it apart from your own.

## Install it on your iPhone

1. In Terminal, in the privmsg folder:

   ```
   scripts/build-ios.sh
   ```

   The first time this takes 10–20 minutes. It downloads Tor for iPhone,
   builds privmsg's core, and prepares the Xcode project.

2. Open `ios/Privmsg.xcodeproj` (double-click it).
3. Connect your iPhone with a cable and pick it at the top of Xcode.
4. Click **Privmsg** in the left column, then **Signing & Capabilities**,
   and choose your Apple ID under **Team** (Add an Account… the first time).
5. Press **Run** (▶).
6. The first time, the iPhone refuses to open it. On the iPhone: Settings →
   General → VPN & Device Management → your Apple ID → Trust. On iOS 16 and
   later, also turn on Settings → Privacy & Security → Developer Mode.

Instead of Xcode you can use SideStore or AltStore: `scripts/build-ios.sh --ipa`
makes `ios/build/privmsg.ipa` for them to sign and install.

## Using it

- First start: choose a password. It can't be recovered.
- **+ → Invite a friend** makes a one-time code. When you're together, they
  scan the QR code; otherwise send them the code.
- **+ → I have an invite code**: paste or scan a code you got.
- In a chat, **⋯** has disappearing messages, the safety number (compare
  it with your friend in person), a new address, and removing the contact.

## What's different from the desktop

- **No notifications.** They would go through Apple. Open the app to get
  messages; the network keeps them for about a day.
- **iOS pauses the app in the background**, so it's only connected while
  it's open (and for a few seconds after). Coming back takes a few seconds
  to reconnect.
- Changing Tor or data use takes effect the next time you open the app.

## Privacy on the phone

- Messages are stored only in the app, encrypted with your password, with
  iOS file protection on top, and **never backed up** to iCloud or a computer.
- The app switcher shows a blank screen, not your chats.
- "Lock when I leave the app" (on by default) asks for the password again.
- Only Apple's keyboard works in the app (other keyboards could send what
  you type anywhere), and autocorrect is off, so the keyboard doesn't learn
  your messages.
- Copied invite codes stay on this phone only (no Universal Clipboard) and
  vanish after 3 minutes.
- Apple knows that your Apple ID installed an app with a random name
  (`scripts/build-ios.sh` picks one for your copy). Your mobile carrier sees
  that the phone uses Tor, not what for.

## For developers

- `crates/mobile` is the Rust layer the app talks to: one `Messenger` object
  (UniFFI, Swift bindings generated into `ios/Privmsg/Generated/`). It runs
  the same `privmsg-node` code as the desktop on a thread of its own, and
  reconnects by itself when the network changes or the app comes back.
  `cargo test -p privmsg-mobile` runs two of them against each other.
- Tor: an iPhone app can't start a `tor` program, so the app links C tor as
  a library (`Tor::start_embedded` in `crates/transport`, feature
  `embedded-tor`), from Tor.framework's prebuilt `tor-nolzma.xcframework`
  (`scripts/fetch-tor-ios.sh` pins its SHA-256). Those builds are not
  reproducible.
- `scripts/build-ios.sh --no-tor` builds for the simulator without the Tor
  library. Then the app starts the `tor` program named by `PRIVMSG_TOR`, as
  the desktop does (the simulator allows that; a phone doesn't).
- The Xcode project is generated from `ios/project.yml` with XcodeGen
  (`brew install xcodegen`); the build script regenerates it when XcodeGen
  is installed.
- Your signing team belongs in `ios/Local.xcconfig` (not in git). Picking a
  Team in Xcode writes it into `project.pbxproj` instead; run
  `scripts/build-ios.sh` again before committing and it moves it back.
- UI tests: `PrivmsgUITests/LiveTests.swift`. `testTalksToDesktop` joins a
  desktop invite over the live network; see the comment at its top.
