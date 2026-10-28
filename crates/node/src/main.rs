//! privmsg — wires Layer 1 (MLS content encryption) on top of
//! Layer 2 (Nym mixnet transport) and runs conversations end to end.
//!
//! The flow this binary implements:
//!
//!   plaintext
//!     └─ privmsg-crypto: MLS encrypt ──► ciphertext
//!          └─ privmsg-transport: pad + Sphinx-wrap + cover traffic ──► mixnet
//!               └─ ...hops, mixed, delayed...
//!                    └─ peer transport: unwrap ──► ciphertext
//!                         └─ peer crypto: MLS decrypt ──► plaintext
//!
//! No layer sees more than its job: the mixnet never sees plaintext; the
//! crypto layer never sees IPs. That separation is the whole design.
//!
//! The logic lives in the `privmsg_node` library (`app` the messenger,
//! `store` the encrypted profile, `wire` the formats, `decoy` the decoy
//! scheduler). This file is the command line; `tui` is the full-screen UI.

mod keychain;
mod tui;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use privmsg_crypto::{Identity, Session};
use privmsg_node::app::{describe_timer, parse_timer, Event, Node};
pub(crate) use privmsg_node::clean;
use privmsg_node::decoy::{self, Scheduler};
use privmsg_node::store::{HistoryEntry, Profile, Settings, MIN_PASSPHRASE};
use privmsg_transport::{DataMode, Mux, NymNetwork, Tor};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::Instant;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

const USAGE: &str = "\
privmsg — metadata-private messenger (MLS over the Nym mixnet)

usage: privmsg [--data-dir DIR] [command]

Just `privmsg` opens the app (and sets it up the first time).

commands:
  init                    create a new encrypted profile
  invite <name> [--qr]    make a one-time invite; whoever uses it becomes <name>
  add <name> <invite>     accept someone's invite and save them as <name>
  ui                      the app (same as plain `privmsg`)
  chat <name>             line-by-line chat with <name> (/quit to leave)
  send <name> <message>   send one message
  listen [seconds]        receive messages until Ctrl-C (or for <seconds>)
  contacts                list contacts, unread counts and open invites
  history <name>          show saved messages with <name>
  disappear <name> [off|5m|1h|1d|1w]
                          show or set disappearing messages with <name> (both sides)
  verify <name>           show the safety number to compare with <name>
  rotate <name>           move the conversation with <name> to a new address
  remove <name>           forget a contact or unused invite and its addresses
  address                 show your mix address for each contact
  decoys [on|off|<secs>]  show or set decoy traffic (mean seconds between sends)
  data [saver|balanced|maximum]
                          show or set how much internet data privmsg uses
  tor [on|off]            show or set hiding your IP address with Tor (default on)
  sleep [off|<minutes>]   show or set auto-sleep: the app stops its cover traffic
                          after <minutes> without typing (default off)
  keychain save|forget    keep the passphrase in the macOS keychain, or stop
  selftest                offline check of the encryption layer

environment:
  PRIVMSG_HOME            profile directory (default ~/.privmsg,
                          or %LOCALAPPDATA%\\privmsg on Windows)
  PRIVMSG_PASSPHRASE      passphrase for scripts (avoid on shared machines)
  RUST_LOG                log filter (default: warn)";

/// Default log filter. The two Nym targets report acks that arrive after
/// our receiver has shut down — routine on every exit, and Nym itself calls
/// it harmless. A real routing failure while running still surfaces as a
/// `recv` error.
const DEFAULT_LOG: &str =
    "warn,privmsg=info,nym_gateway_client::packet_router=error,nym_gateway_client::traits=off";

/// Decoy interval used by `privmsg decoys on`.
const DEFAULT_DECOY_INTERVAL: u32 = 10;

/// How often a running session checks for address rotation and retirement.
pub(crate) const MAINTENANCE_EVERY: Duration = Duration::from_secs(60);

pub(crate) type Network = Mux<NymNetwork>;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let data_dir = take_data_dir(&mut args)?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();

    // Logs would draw over the full-screen app, which shows problems itself.
    // With RUST_LOG set they go to `privmsg.log` in the profile instead.
    let ui = matches!(args.as_slice(), [] | ["ui"]);
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(if ui { "off" } else { DEFAULT_LOG }));
    let logger = tracing_subscriber::fmt().with_env_filter(filter);
    if ui && std::env::var_os("RUST_LOG").is_some() {
        std::fs::create_dir_all(&data_dir)?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(data_dir.join("privmsg.log"))?;
        logger
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(file))
            .init();
    } else {
        logger.with_writer(std::io::stderr).init();
    }

    match args.as_slice() {
        ["selftest"] => selftest(),
        ["init"] => init(data_dir),
        ["address"] => address(data_dir),
        ["invite", name] => invite(data_dir, name, false).await,
        ["invite", name, "--qr"] | ["invite", "--qr", name] => invite(data_dir, name, true).await,
        ["add", name, code] => add(data_dir, name, code).await,
        ["contacts"] => contacts(data_dir),
        ["send", name, words @ ..] if !words.is_empty() => {
            send(data_dir, name, &words.join(" ")).await
        }
        ["listen"] => session(data_dir, None, None).await,
        ["listen", secs] => session(data_dir, None, Some(secs.parse()?)).await,
        ["chat", name] => session(data_dir, Some(name), None).await,
        [] | ["ui"] => start(data_dir).await,
        ["history", name] => history(data_dir, name),
        ["disappear", name] => disappear(data_dir, name, None).await,
        ["disappear", name, after] => disappear(data_dir, name, Some(after)).await,
        ["verify", name] => verify(data_dir, name),
        ["rotate", name] => rotate(data_dir, name).await,
        ["remove", name] => remove(data_dir, name).await,
        ["decoys"] => decoys(data_dir, None),
        ["decoys", setting] => decoys(data_dir, Some(setting)),
        ["data"] => data_mode(data_dir, None),
        ["data", mode] => data_mode(data_dir, Some(mode)),
        ["tor"] => tor(data_dir, None),
        ["tor", setting] => tor(data_dir, Some(setting)),
        ["sleep"] => auto_sleep(data_dir, None),
        ["sleep", setting] => auto_sleep(data_dir, Some(setting)),
        ["keychain", "save"] => keychain_save(data_dir),
        ["keychain", "forget"] => keychain_forget(data_dir),
        ["help"] | ["-h"] | ["--help"] => {
            println!("{USAGE}");
            Ok(())
        }
        _ => bail!("unrecognised command\n\n{USAGE}"),
    }
}

fn take_data_dir(args: &mut Vec<String>) -> Result<PathBuf> {
    if let Some(i) = args.iter().position(|a| a == "--data-dir") {
        args.remove(i);
        if i >= args.len() {
            bail!("--data-dir needs a directory");
        }
        return Ok(PathBuf::from(args.remove(i)));
    }
    if let Some(dir) = std::env::var_os("PRIVMSG_HOME") {
        return Ok(PathBuf::from(dir));
    }
    default_data_dir()
}

#[cfg(not(windows))]
fn default_data_dir() -> Result<PathBuf> {
    let home =
        std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set; use --data-dir"))?;
    Ok(PathBuf::from(home).join(".privmsg"))
}

/// `%LOCALAPPDATA%\privmsg`: Local, not Roaming, so the profile never
/// follows the user to other machines, and outside the folders OneDrive
/// backs up.
#[cfg(windows)]
fn default_data_dir() -> Result<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA")
        .ok_or_else(|| anyhow!("LOCALAPPDATA is not set; use --data-dir"))?;
    Ok(PathBuf::from(local).join("privmsg"))
}

/// The passphrase from `PRIVMSG_PASSPHRASE` or the keychain, if either
/// has one.
fn stored_passphrase(dir: &Path) -> Option<Zeroizing<String>> {
    match std::env::var("PRIVMSG_PASSPHRASE") {
        Ok(p) => Some(Zeroizing::new(p)),
        Err(_) => keychain::get(dir),
    }
}

/// Unlock the profile in `dir`: with the stored passphrase if there is one,
/// otherwise by asking (three tries).
fn open(dir: &Path) -> Result<Node> {
    if let Some(pass) = stored_passphrase(dir) {
        return Node::open(dir, &pass);
    }
    if !Profile::exists(dir) {
        bail!(
            "no profile in {} yet: run `privmsg` to set one up",
            dir.display()
        );
    }
    let mut tries = 0;
    loop {
        let pass = Zeroizing::new(rpassword::prompt_password("Password: ")?);
        match Node::open(dir, &pass) {
            Err(e) if e.to_string().contains("wrong passphrase") && tries < 2 => {
                tries += 1;
                eprintln!("That password didn't work. Try again.");
            }
            result => return result,
        }
    }
}

/// First-run setup: choose a passphrase, create the profile, and on macOS
/// offer to remember the passphrase in the keychain.
fn setup(dir: &Path) -> Result<Node> {
    if let Ok(pass) = std::env::var("PRIVMSG_PASSPHRASE") {
        if pass.chars().count() < MIN_PASSPHRASE {
            bail!("PRIVMSG_PASSPHRASE must be at least {MIN_PASSPHRASE} characters");
        }
        return Node::create(dir, &pass);
    }
    eprintln!(
        "Welcome to privmsg!\n\n\
         Choose a password (at least 12 characters). It locks your messages on\n\
         this computer. It can't be recovered, so pick one you'll remember.\n\
         Tip: four random words, like \"maple cloud river tiger\", are strong\n\
         and easy to remember.\n"
    );
    let pass = loop {
        let pass = Zeroizing::new(rpassword::prompt_password("Password: ")?);
        if pass.chars().count() < MIN_PASSPHRASE {
            eprintln!("Please use at least {MIN_PASSPHRASE} characters.");
            continue;
        }
        if *pass != *Zeroizing::new(rpassword::prompt_password("Type it again: ")?) {
            eprintln!("Those didn't match. Let's try again.");
            continue;
        }
        break pass;
    };
    let node = Node::create(dir, &pass)?;
    if cfg!(target_os = "macos")
        && ask(
            "\nRemember the password in this Mac's Keychain, so you don't have to type it? [Y/n] ",
        )?
    {
        match keychain::set(dir, &pass) {
            Ok(()) => eprintln!("Saved. (`privmsg keychain forget` undoes this.)"),
            Err(e) => eprintln!("Couldn't save it ({e:#}); you'll be asked each time."),
        }
    }
    Ok(node)
}

/// A yes/no question; Enter alone means yes.
fn ask(question: &str) -> Result<bool> {
    eprint!("{question}");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(!answer.trim().to_lowercase().starts_with('n'))
}

/// Plain `privmsg`: set up on first run, then open the app.
async fn start(dir: PathBuf) -> Result<()> {
    let node = if Profile::exists(&dir) {
        open(&dir)?
    } else {
        setup(&dir)?
    };
    tui::run(node).await
}

/// A multiplexer over this profile's Nym addresses, with `slots` online.
pub(crate) async fn connect(node: &mut Node, slots: &[String]) -> Result<Network> {
    let mut net = NymNetwork::new(node.slots_dir(), node.settings().data_mode);
    // Even with nothing to open yet: the app opens addresses later (invites).
    if node.settings().tor {
        eprintln!("Starting Tor, so the network can't see your IP address…");
        let tor = Tor::start(&node.tor_dir(), |percent| eprint!("\r  Tor: {percent}%  "))
            .await
            .context("start Tor")?;
        eprintln!();
        net = net.with_tor(tor)?;
    }
    let mut mux = Mux::new(net);
    eprintln!("Connecting securely through the Nym network (about 10 seconds)…");
    node.connect(&mut mux, slots).await?;
    Ok(mux)
}

/// Full content-layer exercise with no network. Proves Layer 1 end to end.
fn selftest() -> Result<()> {
    let alice = Identity::new("alice-local-label")?;
    let bob = Identity::new("bob-local-label")?;

    let mut alice_session = Session::create(&alice)?;
    let welcome = alice_session.add_member(&alice, bob.key_package()?)?;
    let mut bob_session = Session::join(&bob, &welcome)?;

    let ct = alice_session.encrypt(&alice, b"hello over the mixnet")?;
    tracing::info!(
        ciphertext_len = ct.len(),
        "alice -> (this is what crosses the wire)"
    );
    let pt = bob_session.decrypt(&bob, &ct)?;
    tracing::info!(plaintext = %String::from_utf8_lossy(&pt), "bob decrypted");

    assert_eq!(pt, b"hello over the mixnet");
    println!("selftest OK: MLS content layer verified end to end (no network).");
    Ok(())
}

fn init(dir: PathBuf) -> Result<()> {
    if Profile::exists(&dir) {
        bail!("a profile already exists in {}", dir.display());
    }
    setup(&dir)?;
    println!("profile created in {}", dir.display());
    println!("next: run `privmsg` to open the app");
    Ok(())
}

fn address(dir: PathBuf) -> Result<()> {
    let node = open(&dir)?;
    let show = |a: &str| {
        if a.is_empty() {
            "(known after the next connection)".to_string()
        } else {
            a.to_string()
        }
    };
    if node.contacts().is_empty() && node.invites().is_empty() {
        println!("no addresses yet: each contact and invite gets its own");
    }
    for c in node.contacts() {
        println!("{}: {}", clean(&c.name), show(&c.slot.address));
    }
    for i in node.invites() {
        println!("{} (invite): {}", clean(&i.name), show(&i.slot.address));
    }
    Ok(())
}

async fn invite(dir: PathBuf, name: &str, qr: bool) -> Result<()> {
    let mut node = open(&dir)?;
    let mut mux = connect(&mut node, &[]).await?;
    let code = node.create_invite(&mut mux, name).await;
    mux.close().await;
    let code = code?;
    if qr {
        println!("{}", qr_code(&code)?);
    }
    println!("{code}");
    eprintln!(
        "\nGive this code to {name} over a channel you trust. It works once.\n\
         Then run `privmsg listen` (or `ui`) to receive their join."
    );
    Ok(())
}

/// The invite as a QR code made of Unicode half blocks, light on dark like
/// `qrencode -t UTF8`; phone cameras read either polarity.
fn qr_code(text: &str) -> Result<String> {
    use qrcode::render::unicode::Dense1x2;
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::L)
        .context("invite too long for a QR code")?;
    Ok(code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}

async fn add(dir: PathBuf, name: &str, code: &str) -> Result<()> {
    let mut node = open(&dir)?;
    let mut mux = connect(&mut node, &[]).await?;
    let result = node.accept_invite(&mut mux, code, name).await;
    mux.close().await;
    result?;
    println!("{name} added. They will see you as soon as they are online; `privmsg chat {name}` to talk.");
    Ok(())
}

fn contacts(dir: PathBuf) -> Result<()> {
    let node = open(&dir)?;
    if node.contacts().is_empty() && node.invites().is_empty() {
        println!("no contacts yet — `privmsg invite <name>` or `privmsg add <name> <invite>`");
    }
    for c in node.contacts() {
        let unread = match c.unread {
            0 => String::new(),
            n => format!(", {n} unread"),
        };
        println!("{}  ({} messages{unread})", clean(&c.name), c.history.len());
    }
    for i in node.invites() {
        println!("{}  (invite not used yet)", clean(&i.name));
    }
    Ok(())
}

async fn send(dir: PathBuf, name: &str, text: &str) -> Result<()> {
    let mut node = open(&dir)?;
    let current = node.slots_for(name)?.swap_remove(0);
    let mut mux = connect(&mut node, &[current]).await?;
    let result = async {
        node.maintain(&mut mux).await?;
        node.send_text(&mut mux, name, text).await
    }
    .await;
    mux.close().await;
    result?;
    println!("sent.");
    Ok(())
}

async fn disappear(dir: PathBuf, name: &str, after: Option<&str>) -> Result<()> {
    let mut node = open(&dir)?;
    if let Some(after) = after {
        let after = parse_timer(after)?;
        // Only the sender is needed; nothing has to be received.
        let mut mux = connect(&mut node, &[]).await?;
        let result = node.set_timer(&mut mux, name, after).await;
        mux.close().await;
        result?;
    }
    match node.contact(name)?.disappear_after {
        None => println!("disappearing messages with {name}: off"),
        Some(secs) => println!(
            "messages with {name} disappear after {} — here and in {name}'s app",
            describe_timer(Some(secs))
        ),
    }
    Ok(())
}

fn verify(dir: PathBuf, name: &str) -> Result<()> {
    let node = open(&dir)?;
    println!(
        "Safety number with {}:\n\n    {}\n",
        clean(name),
        node.safety_number(name)?
    );
    println!(
        "Compare it with {} in person or on a call (not in a chat app). If it\n\
         matches, nobody intercepted your invite. If it doesn't, remove the\n\
         contact and connect again with a new invite.",
        clean(name)
    );
    Ok(())
}

async fn rotate(dir: PathBuf, name: &str) -> Result<()> {
    let mut node = open(&dir)?;
    let slots = node.slots_for(name)?;
    let mut mux = connect(&mut node, &slots).await?;
    let result = node.rotate(&mut mux, name).await;
    mux.close().await;
    result?;
    println!("{name} now writes to a new address. The old one keeps listening until they confirm.");
    Ok(())
}

async fn remove(dir: PathBuf, name: &str) -> Result<()> {
    let mut node = open(&dir)?;
    // Removing only deletes local keys; nothing needs to be online.
    let mut mux = Mux::new(NymNetwork::new(node.slots_dir(), node.settings().data_mode));
    node.remove(&mut mux, name).await?;
    println!("{name} removed, with its addresses and conversation keys.");
    Ok(())
}

fn decoys(dir: PathBuf, setting: Option<&str>) -> Result<()> {
    let mut node = open(&dir)?;
    if let Some(setting) = setting {
        let decoy_interval = match setting {
            "off" => None,
            "on" => Some(DEFAULT_DECOY_INTERVAL),
            secs => match secs.parse::<u32>() {
                Ok(n) if n >= decoy::MIN_INTERVAL => Some(n),
                _ => bail!(
                    "use `on`, `off` or a number of seconds (at least {})",
                    decoy::MIN_INTERVAL
                ),
            },
        };
        node.set_settings(Settings {
            decoy_interval,
            ..node.settings().clone()
        })?;
    }
    match node.settings().decoy_interval {
        None => println!("decoys off: messages go out as soon as you send them"),
        Some(n) => println!(
            "decoys on: while connected, each conversation sends a message or a decoy \
             every ~{n}s at random; your messages wait for the next one"
        ),
    }
    Ok(())
}

fn data_mode(dir: PathBuf, setting: Option<&str>) -> Result<()> {
    let mut node = open(&dir)?;
    if let Some(setting) = setting {
        node.set_settings(Settings {
            data_mode: setting.parse()?,
            ..node.settings().clone()
        })?;
    }
    let current = node.settings().data_mode;
    for mode in DataMode::ALL {
        let mark = if mode == current { "→" } else { " " };
        let about = match mode {
            DataMode::Saver => "messages take a few seconds",
            DataMode::Balanced => "messages take a second or two, more cover",
            DataMode::Maximum => "instant, the most cover; heavy on data",
        };
        println!(
            "{mark} {:<9} ~{} MB an hour, plus ~{} per contact, while open; {about}",
            mode.name(),
            mode.mb_per_hour(),
            mode.slot_mb_per_hour()
        );
    }
    println!("Nothing is used while privmsg is closed. Changes apply the next time it connects.");
    Ok(())
}

fn auto_sleep(dir: PathBuf, setting: Option<&str>) -> Result<()> {
    let mut node = open(&dir)?;
    if let Some(setting) = setting {
        let auto_sleep = match setting {
            "off" => None,
            mins => match mins.parse::<u32>() {
                Ok(n) if n >= 1 => Some(n),
                _ => bail!("use `off` or a number of minutes, like `privmsg sleep 10`"),
            },
        };
        node.set_settings(Settings {
            auto_sleep,
            ..node.settings().clone()
        })?;
    }
    match node.settings().auto_sleep {
        None => println!(
            "auto-sleep off: while the app is open its cover traffic never stops, so \
             nobody watching your connection can tell when you are actually chatting"
        ),
        Some(n) => println!(
            "auto-sleep on: after {n} minutes without typing the app stops its cover traffic \
             (you still receive messages) and starts it again when you type. Saves data, but \
             someone watching your connection can see when you are active."
        ),
    }
    if node.settings().decoy_interval.is_some() {
        println!("(decoys are on, which keeps the app sending, so it never sleeps)");
    }
    Ok(())
}

fn tor(dir: PathBuf, setting: Option<&str>) -> Result<()> {
    let mut node = open(&dir)?;
    if let Some(setting) = setting {
        let tor = match setting {
            "on" => true,
            "off" => false,
            _ => bail!("use `on` or `off`"),
        };
        node.set_settings(Settings {
            tor,
            ..node.settings().clone()
        })?;
    }
    if node.settings().tor {
        println!(
            "Tor on: privmsg reaches the Nym network through Tor, so the Nym servers \
             and your network never see your IP address together with privmsg."
        );
    } else {
        println!(
            "Tor off: the first Nym server you connect to sees your IP address (not your \
             messages or who you talk to). Turn it back on with `privmsg tor on`."
        );
    }
    Ok(())
}

fn keychain_save(dir: PathBuf) -> Result<()> {
    let pass = match std::env::var("PRIVMSG_PASSPHRASE") {
        Ok(p) => Zeroizing::new(p),
        Err(_) => Zeroizing::new(rpassword::prompt_password("Password: ")?),
    };
    Node::open(&dir, &pass)?;
    keychain::set(&dir, &pass)?;
    println!("passphrase saved in your keychain; privmsg will no longer ask for it.");
    Ok(())
}

fn keychain_forget(dir: PathBuf) -> Result<()> {
    if keychain::delete(&dir)? {
        println!("passphrase removed from your keychain.");
    } else {
        println!("no passphrase for this profile in your keychain.");
    }
    Ok(())
}

/// `listen`, or with `chat_with`, `chat`: receive on every open address,
/// keep addresses maintained and run decoys if they are on.
async fn session(dir: PathBuf, chat_with: Option<&str>, seconds: Option<u64>) -> Result<()> {
    let mut node = open(&dir)?;
    if let Some(name) = chat_with {
        let history = &node.contact(name)?.history;
        for entry in &history[history.len().saturating_sub(10)..] {
            print_entry(name, entry);
        }
        node.mark_read(name)?;
    }
    let decoy_interval = node.settings().decoy_interval;
    // Decoys must cover every conversation, so they need every address.
    let slots = match chat_with {
        Some(name) if decoy_interval.is_none() => node.slots_for(name)?,
        _ => node.all_slots(),
    };
    let mut mux = connect(&mut node, &slots).await?;
    node.maintain(&mut mux).await?;
    let mut scheduler = decoy_interval.map(|secs| {
        Scheduler::new(
            Duration::from_secs(secs.into()),
            node.contacts().iter().map(|c| c.name.clone()),
        )
    });
    match chat_with {
        Some(_) => eprintln!("connected — type a message and press Enter; /quit to leave"),
        None => eprintln!("listening on {} addresses (Ctrl-C to stop)", slots.len()),
    }
    if let Some(n) = decoy_interval {
        eprintln!("decoys on: messages leave at random moments, ~{n}s apart on average");
    }

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut maintenance =
        tokio::time::interval_at(Instant::now() + MAINTENANCE_EVERY, MAINTENANCE_EVERY);
    let deadline = tokio::time::sleep(Duration::from_secs(seconds.unwrap_or(u64::MAX / 4)));
    tokio::pin!(deadline);
    let result = loop {
        let next_tick = scheduler.as_ref().and_then(Scheduler::next_due);
        let tick_at = next_tick.as_ref().map_or_else(far_future, |(_, at)| *at);
        tokio::select! {
            msg = mux.recv() => match msg {
                Ok((slot, msg)) => {
                    receive(&mut node, &mut mux, &slot, &msg.payload, scheduler.as_mut()).await
                }
                Err(e) => break Err(e),
            },
            line = lines.next_line(), if chat_with.is_some() => match line {
                Ok(Some(line)) if line.trim() == "/quit" => break Ok(()),
                Ok(Some(line)) if line.trim().is_empty() => {}
                Ok(Some(line)) => {
                    let name = chat_with.expect("chat mode");
                    match scheduler.as_mut() {
                        Some(s) => s.queue(name, line),
                        None => {
                            if let Err(e) = node.send_text(&mut mux, name, &line).await {
                                eprintln!("! not sent: {e:#}");
                            }
                        }
                    }
                }
                Ok(None) => break Ok(()),
                Err(e) => break Err(e.into()),
            },
            _ = tokio::time::sleep_until(tick_at), if next_tick.is_some() => {
                let (name, _) = next_tick.expect("tick scheduled");
                let s = scheduler.as_mut().expect("decoys on");
                tick(&mut node, &mut mux, s, &name).await;
            }
            _ = maintenance.tick() => {
                if let Err(e) = node.maintain(&mut mux).await {
                    tracing::warn!("address maintenance failed: {e:#}");
                }
            }
            _ = &mut deadline => break Ok(()),
            _ = tokio::signal::ctrl_c() => break Ok(()),
        }
    };
    if let Some(s) = scheduler.as_mut() {
        flush_queued(&mut node, &mut mux, s).await;
    }
    mux.close().await;
    result
}

/// One decoy-clock tick for `name`: their oldest queued message, or a decoy.
pub(crate) async fn tick(node: &mut Node, mux: &mut Network, s: &mut Scheduler, name: &str) {
    match s.tick(name) {
        Some(text) => {
            if let Err(e) = node.send_text(mux, name, &text).await {
                eprintln!("! not sent to {}: {e:#}", clean(name));
            }
        }
        None => {
            if let Err(e) = node.send_decoy(mux, name).await {
                tracing::warn!("decoy to {name} not sent: {e:#}");
            }
        }
    }
}

/// Send what the decoy clock had not got to yet, so quitting loses nothing.
pub(crate) async fn flush_queued(node: &mut Node, mux: &mut Network, s: &mut Scheduler) {
    for (name, text) in s.drain() {
        if let Err(e) = node.send_text(mux, &name, &text).await {
            eprintln!("! not sent to {}: {e:#}", clean(&name));
        }
    }
}

pub(crate) fn far_future() -> Instant {
    Instant::now() + Duration::from_secs(86_400 * 365)
}

fn history(dir: PathBuf, name: &str) -> Result<()> {
    let mut node = open(&dir)?;
    let contact = node.contact(name)?;
    if contact.history.is_empty() {
        println!("no messages with {name} yet");
    }
    for entry in &contact.history {
        print_entry(name, entry);
    }
    node.mark_read(name)
}

async fn receive(
    node: &mut Node,
    mux: &mut Network,
    slot: &str,
    payload: &[u8],
    scheduler: Option<&mut Scheduler>,
) {
    match node.handle_incoming(mux, slot, payload).await {
        Ok(events) => {
            let mut scheduler = scheduler;
            for event in events {
                match event {
                    Event::Joined { contact } => {
                        println!("* {} accepted your invite", clean(&contact));
                        if let Some(s) = scheduler.as_deref_mut() {
                            s.add(contact);
                        }
                    }
                    Event::Message { contact, text } => {
                        println!("{}: {}", clean(&contact), clean(&text));
                        if let Err(e) = node.mark_read(&contact) {
                            tracing::warn!("{e:#}");
                        }
                    }
                    Event::Timer { contact, after } => println!(
                        "* {} set disappearing messages to {}",
                        clean(&contact),
                        describe_timer(after)
                    ),
                }
            }
        }
        Err(e) => tracing::warn!("ignored an incoming message: {e:#}"),
    }
}

fn print_entry(name: &str, entry: &HistoryEntry) {
    let who = if entry.outgoing { "me" } else { name };
    println!("[{}] {}: {}", utc(entry.at), clean(who), clean(&entry.text));
}

/// `YYYY-MM-DD HH:MM` in UTC (days-from-civil, Howard Hinnant's algorithm).
pub(crate) fn utc(unix: u64) -> String {
    let (days, secs) = ((unix / 86_400) as i64, unix % 86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}",
        secs / 3600,
        secs % 3600 / 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_formatting() {
        assert_eq!(utc(0), "1970-01-01 00:00");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00");
        assert_eq!(utc(1_792_580_000), "2026-10-21 10:53");
    }

    #[test]
    fn control_characters_are_neutralised() {
        assert_eq!(clean("hi\x1b[2Jthere\n"), "hi\u{FFFD}[2Jthere\u{FFFD}");
        assert_eq!(clean("ünïcödé ok"), "ünïcödé ok");
        assert_eq!(clean("abc\u{202E}fed"), "abc\u{FFFD}fed", "bidi override");
        assert_eq!(clean("a\u{061C}b"), "a\u{FFFD}b", "Arabic letter mark");
    }

    #[test]
    fn invite_qr_code_renders() -> Result<()> {
        let code = format!("privmsg1:{}", "A".repeat(700));
        let qr = qr_code(&code)?;
        assert!(qr.lines().count() > 20);
        assert!(
            qr_code(&"A".repeat(5000)).is_err(),
            "too long for any QR version"
        );
        Ok(())
    }

    #[test]
    fn data_dir_flag_is_extracted() -> Result<()> {
        let mut args = vec!["--data-dir".to_string(), "/tmp/x".into(), "contacts".into()];
        assert_eq!(take_data_dir(&mut args)?, PathBuf::from("/tmp/x"));
        assert_eq!(args, vec!["contacts".to_string()]);
        assert!(take_data_dir(&mut vec!["--data-dir".to_string()]).is_err());
        Ok(())
    }
}
