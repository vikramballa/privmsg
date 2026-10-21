//! Phase 1 node — wires Layer 1 (MLS content encryption) on top of
//! Layer 2 (Nym mixnet transport) and runs two-party conversations end to end.
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
//! `app` holds the messenger logic, `store` the encrypted profile, `wire`
//! the on-the-wire formats. This file is only the command line.

mod app;
mod store;
mod wire;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use privmsg_crypto::{Identity, Session};
use privmsg_transport::{NymTransport, Transport};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

use app::{Event, Node};

const USAGE: &str = "\
privmsg — metadata-private messenger (MLS over the Nym mixnet)

usage: privmsg [--data-dir DIR] <command>

commands:
  init                    create a new encrypted profile
  address                 print your mix address
  invite <name>           make a one-time invite; whoever uses it becomes <name>
  add <name> <invite>     accept someone's invite and save them as <name>
  contacts                list contacts and open invites
  send <name> <message>   send one message
  listen [seconds]        receive messages until Ctrl-C (or for <seconds>)
  chat <name>             interactive chat with <name> (/quit to leave)
  history <name>          show saved messages with <name>
  selftest                offline check of the encryption layer

environment:
  PRIVMSG_HOME            profile directory (default ~/.privmsg)
  PRIVMSG_PASSPHRASE      passphrase for scripts (avoid on shared machines)
  RUST_LOG                log filter (default: warn)";

/// Default log filter. The two Nym targets report acks that arrive after
/// our receiver has shut down — routine on every exit, and Nym itself calls
/// it harmless. A real routing failure while running still surfaces as a
/// `recv` error.
const DEFAULT_LOG: &str =
    "warn,privmsg=info,nym_gateway_client::packet_router=error,nym_gateway_client::traits=off";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG)),
        )
        .with_writer(std::io::stderr)
        .init();

    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let data_dir = take_data_dir(&mut args)?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();

    match args.as_slice() {
        ["selftest"] => selftest(),
        ["init"] => init(data_dir),
        ["address"] => address(data_dir).await,
        ["invite", name] => invite(data_dir, name).await,
        ["add", name, code] => add(data_dir, name, code).await,
        ["contacts"] => contacts(data_dir),
        ["send", name, words @ ..] if !words.is_empty() => {
            send(data_dir, name, &words.join(" ")).await
        }
        ["listen"] => listen(data_dir, None).await,
        ["listen", secs] => listen(data_dir, Some(secs.parse()?)).await,
        ["chat", name] => chat(data_dir, name).await,
        ["history", name] => history(data_dir, name),
        [] | ["help"] | ["-h"] | ["--help"] => {
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
    let home =
        std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set; use --data-dir"))?;
    Ok(PathBuf::from(home).join(".privmsg"))
}

fn passphrase(confirm: bool) -> Result<Zeroizing<String>> {
    let pass = match std::env::var("PRIVMSG_PASSPHRASE") {
        Ok(p) => Zeroizing::new(p),
        Err(_) => {
            let p = Zeroizing::new(rpassword::prompt_password("passphrase: ")?);
            if confirm && *p != *Zeroizing::new(rpassword::prompt_password("repeat passphrase: ")?)
            {
                bail!("passphrases do not match");
            }
            p
        }
    };
    if confirm && pass.chars().count() < 8 {
        bail!("use a passphrase of at least 8 characters");
    }
    Ok(pass)
}

fn open(dir: &Path) -> Result<Node> {
    Node::open(dir, &passphrase(false)?)
}

async fn connect(node: &Node) -> Result<NymTransport> {
    eprintln!("connecting to the Nym mixnet…");
    NymTransport::connect(&node.nym_dir()).await
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
    Node::create(&dir, &passphrase(true)?)?;
    println!("profile created in {}", dir.display());
    println!("next: `privmsg invite <name>` to invite someone, or `privmsg add <name> <invite>`");
    Ok(())
}

async fn address(dir: PathBuf) -> Result<()> {
    let node = open(&dir)?;
    let transport = connect(&node).await?;
    println!("{}", transport.address().0);
    transport.disconnect().await;
    Ok(())
}

async fn invite(dir: PathBuf, name: &str) -> Result<()> {
    let mut node = open(&dir)?;
    let transport = connect(&node).await?;
    let code = node.create_invite(&transport.address(), name)?;
    transport.disconnect().await;
    println!("{code}");
    eprintln!(
        "\nGive this code to {name} over a channel you trust. It works once.\n\
         Then run `privmsg listen` (or `chat {name}`) to receive their join."
    );
    Ok(())
}

async fn add(dir: PathBuf, name: &str, code: &str) -> Result<()> {
    let mut node = open(&dir)?;
    let mut transport = connect(&node).await?;
    let result = node.accept_invite(&mut transport, code, name).await;
    transport.disconnect().await;
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
        println!("{}  ({} messages)", c.name, c.history.len());
    }
    for i in node.invites() {
        println!("{}  (invite not used yet)", i.name);
    }
    Ok(())
}

async fn send(dir: PathBuf, name: &str, text: &str) -> Result<()> {
    let mut node = open(&dir)?;
    node.contact(name)?;
    let mut transport = connect(&node).await?;
    let result = node.send_text(&mut transport, name, text).await;
    transport.disconnect().await;
    result?;
    println!("sent.");
    Ok(())
}

async fn listen(dir: PathBuf, seconds: Option<u64>) -> Result<()> {
    let mut node = open(&dir)?;
    let mut transport = connect(&node).await?;
    eprintln!("listening as {} (Ctrl-C to stop)", transport.address().0);

    let deadline = tokio::time::sleep(Duration::from_secs(seconds.unwrap_or(u64::MAX / 4)));
    tokio::pin!(deadline);
    let result = loop {
        tokio::select! {
            msg = transport.recv() => match msg {
                Ok(msg) => receive(&mut node, &msg.payload),
                Err(e) => break Err(e),
            },
            _ = &mut deadline => break Ok(()),
            _ = tokio::signal::ctrl_c() => break Ok(()),
        }
    };
    transport.disconnect().await;
    result
}

async fn chat(dir: PathBuf, name: &str) -> Result<()> {
    let mut node = open(&dir)?;
    let history = &node.contact(name)?.history;
    for entry in &history[history.len().saturating_sub(10)..] {
        print_entry(name, entry);
    }
    let mut transport = connect(&node).await?;
    eprintln!("connected — type a message and press Enter; /quit to leave");

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let result = loop {
        tokio::select! {
            msg = transport.recv() => match msg {
                Ok(msg) => receive(&mut node, &msg.payload),
                Err(e) => break Err(e),
            },
            line = lines.next_line() => match line {
                Ok(Some(line)) if line.trim() == "/quit" => break Ok(()),
                Ok(Some(line)) if line.trim().is_empty() => {}
                Ok(Some(line)) => {
                    if let Err(e) = node.send_text(&mut transport, name, &line).await {
                        eprintln!("! not sent: {e:#}");
                    }
                }
                Ok(None) => break Ok(()),
                Err(e) => break Err(e.into()),
            },
            _ = tokio::signal::ctrl_c() => break Ok(()),
        }
    };
    transport.disconnect().await;
    result
}

fn history(dir: PathBuf, name: &str) -> Result<()> {
    let node = open(&dir)?;
    let contact = node.contact(name)?;
    if contact.history.is_empty() {
        println!("no messages with {name} yet");
    }
    for entry in &contact.history {
        print_entry(name, entry);
    }
    Ok(())
}

fn receive(node: &mut Node, payload: &[u8]) {
    match node.handle_incoming(payload) {
        Ok(events) => {
            for event in events {
                match event {
                    Event::Joined { contact } => {
                        println!("* {} accepted your invite", clean(&contact))
                    }
                    Event::Message { contact, text } => {
                        println!("{}: {}", clean(&contact), clean(&text))
                    }
                }
            }
        }
        Err(e) => tracing::warn!("ignored an incoming message: {e:#}"),
    }
}

fn print_entry(name: &str, entry: &store::HistoryEntry) {
    let who = if entry.outgoing { "me" } else { name };
    println!("[{}] {}: {}", utc(entry.at), clean(who), clean(&entry.text));
}

/// Strip control characters so a contact can't send terminal escape
/// sequences that rewrite the screen.
fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}

/// `YYYY-MM-DD HH:MM` in UTC (days-from-civil, Howard Hinnant's algorithm).
fn utc(unix: u64) -> String {
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
