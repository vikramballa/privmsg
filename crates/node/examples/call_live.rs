//! A real call over Tor and the Nym mixnet, between two programs on this
//! machine, with made-up audio: each side beeps for 100 ms every 4 seconds
//! (bob two seconds after alice) and listens for the other's beeps the way a
//! speaker would, 10 ms at a time. Reports how long each beep took from
//! "microphone" to "speaker", and how many never came.
//!
//! cargo run --release -p privmsg-node --example call_live -- bob <dir> <secs> &
//! cargo run --release -p privmsg-node --example call_live -- alice <dir> <secs>
//!
//! Each side makes a throwaway profile in <dir>/<name>; the invite goes
//! through <dir>/invite.txt. Tor is found as privmsg finds it (PRIVMSG_TOR).
//! CALL_MIC_MS=100 hands the "microphone" over in 100 ms lumps, the way an
//! iPhone's microphone tap does (default: every 10 ms, like a computer).

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use privmsg_node::app::{Event, Node};
use privmsg_node::call::{AudioPipe, CallUpdate, Calls, RATE};
use privmsg_transport::{Mux, NymNetwork, Tor};
use tokio::time::{interval, Instant};

const PASS: &str = "call live test passphrase";
const BEEP_EVERY_MS: u64 = 4000;
const BEEP_MS: u64 = 100;
const BLOCK: usize = RATE as usize / 100;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let [_, who, dir, secs] = args.as_slice() else {
        bail!("usage: call_live alice|bob <dir> <talk seconds>");
    };
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(false)
        .init();
    let talk = Duration::from_secs(secs.parse()?);
    let dir = Path::new(dir);
    let me = dir.join(who);
    let mut node = Node::create(&me, PASS)?;

    let started = Instant::now();
    let tor = Tor::start(&node.tor_dir(), |_| {}).await?;
    let net = NymNetwork::new(node.nym_keys(), node.settings().data_mode).with_tor(tor)?;
    let mut mux = Mux::new(net);
    let mut calls = Calls::new(AudioPipe::default(), None);
    say(
        who,
        &format!("Tor up in {:.0} s", started.elapsed().as_secs_f64()),
    );

    let invite = dir.join("invite.txt");
    let peer = if who == "bob" {
        let code = node.create_invite(&mut mux, "alice").await?;
        std::fs::write(&invite, code)?;
        say(who, "invite written; waiting for alice");
        "alice"
    } else {
        let code = loop {
            if let Ok(code) = std::fs::read_to_string(&invite) {
                if !code.is_empty() {
                    break code;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        };
        let slots = node.all_slots();
        node.connect(&mut mux, &slots).await?;
        node.accept_invite(&mut mux, &code, "bob").await?;
        say(who, "joined bob; calling in 20 s");
        "bob"
    };

    // Beeps: alice on the even seconds, bob on the odd ones.
    let (mine, theirs) = if who == "alice" { (0, 2000) } else { (2000, 0) };
    let mut call_at = (who == "alice").then(|| Instant::now() + Duration::from_secs(20));
    let mut talking_since: Option<Instant> = None;
    let mut ten_ms = interval(Duration::from_millis(10));
    let mic_every: u64 = std::env::var("CALL_MIC_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);
    let mut sample_clock: Option<u64> = None; // samples pushed, as wall-clock ms
    let mut loud = false;
    let mut heard: Vec<u64> = Vec::new(); // latency of each beep heard, ms
    let mut quiet_in_beep = 0u32; // 10 ms blocks of silence inside a beep heard
    let deadline = Instant::now() + Duration::from_secs(600);
    let mut ended = false;

    loop {
        if Instant::now() > deadline {
            bail!("gave up after 10 minutes");
        }
        if talking_since.is_some_and(|t| t.elapsed() > talk) && !ended {
            if who == "alice" {
                calls.hang_up(&mut node, &mut mux).await;
            }
            ended = true;
        }
        if ended && !calls.is_busy() {
            break;
        }
        let ring_until = calls.deadline();
        tokio::select! {
            arrived = mux.recv() => {
                let (slot, msg) = arrived?;
                let events = match node.handle_incoming(&mut mux, &slot, &msg.payload).await {
                    Ok(events) => events,
                    Err(e) => { say(who, &format!("ignored: {e:#}")); continue }
                };
                for event in events {
                    match event {
                        Event::Joined { contact } => say(who, &format!("{contact} joined")),
                        Event::Call { contact, signal } => {
                            let update = calls.on_signal(&mut node, &mut mux, &contact, signal).await;
                            if matches!(update, Some(CallUpdate::Ringing { .. })) {
                                say(who, "ringing; answering");
                                calls.accept(&mux)?;
                            }
                            note(who, &update, &mut talking_since);
                            if matches!(update, Some(CallUpdate::Ended { .. })) { ended = true; }
                        }
                        _ => {}
                    }
                }
            }
            news = calls.next() => {
                let update = calls.on_news(&mut node, &mut mux, news).await;
                note(who, &update, &mut talking_since);
                if matches!(update, Some(CallUpdate::Ended { .. })) { ended = true; }
            }
            _ = tokio::time::sleep_until(ring_until.unwrap_or(deadline)), if ring_until.is_some() => {
                let update = calls.check(&mut node, &mut mux).await;
                note(who, &update, &mut talking_since);
            }
            _ = tokio::time::sleep_until(call_at.unwrap_or(deadline)), if call_at.is_some() => {
                call_at = None;
                say(who, &format!("calling {peer}"));
                calls.start(&mut node, &mut mux, peer).await?;
            }
            _ = ten_ms.tick(), if talking_since.is_some() => {
                // Microphone: whatever wall-clock time has passed, beeping in
                // our slots.
                let now = now_ms();
                let from = *sample_clock.get_or_insert(now);
                let mic_due = now - from >= mic_every;
                let mut pcm = Vec::new();
                let mut t = from as f64;
                let step = 1000.0 / f64::from(RATE);
                while (t as u64) < now {
                    let in_beep = (t as u64 + BEEP_EVERY_MS - mine) % BEEP_EVERY_MS < BEEP_MS;
                    pcm.push(if in_beep { (t * 2.0 * std::f64::consts::PI).sin() as f32 * 0.5 } else { 0.0 });
                    t += step;
                }
                if mic_due {
                    sample_clock = Some(now);
                    calls.audio().push_mic(&pcm);
                }
                // Speaker: 10 ms, as a sound card would take it.
                let mut out = vec![0.0f32; BLOCK];
                calls.audio().pull_speaker(&mut out);
                let level = out.iter().fold(0.0f32, |m, s| m.max(s.abs()));
                if level > 0.1 && !loud {
                    // When the beep we hear began: their most recent slot.
                    let begun = (now + BEEP_EVERY_MS * 10 - theirs) % BEEP_EVERY_MS;
                    heard.push(begun);
                } else if loud && level < 0.02 {
                    if let Some(&last) = heard.last() {
                        // Still within the 100 ms the beep should last?
                        let since_start = (now + BEEP_EVERY_MS * 10 - theirs) % BEEP_EVERY_MS;
                        if since_start < last + BEEP_MS - 20 {
                            quiet_in_beep += 1;
                        }
                    }
                }
                loud = level > 0.05;
            }
        }
    }

    let talked = talk.as_millis() as u64;
    let expected = talked / BEEP_EVERY_MS;
    let mut sorted = heard.clone();
    sorted.sort_unstable();
    let pct = |p: f64| {
        sorted
            .get(((sorted.len().max(1) - 1) as f64 * p) as usize)
            .copied()
            .unwrap_or(0)
    };
    say(
        who,
        &format!(
            "RESULT heard {} of ~{expected} beeps; delay ms median {} p90 {} p99 {} max {}; \
             silent 10 ms blocks inside heard beeps: {quiet_in_beep}",
            heard.len(),
            pct(0.5),
            pct(0.9),
            pct(0.99),
            sorted.last().copied().unwrap_or(0)
        ),
    );
    // Let the line's tail and the end signal go out.
    tokio::time::sleep(Duration::from_secs(16)).await;
    mux.close().await;
    Ok(())
}

fn note(who: &str, update: &Option<CallUpdate>, talking_since: &mut Option<Instant>) {
    if let Some(update) = update {
        say(who, &format!("{update:?}"));
        if matches!(update, CallUpdate::Talking { .. }) {
            talking_since.get_or_insert_with(Instant::now);
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .context("clock")
        .unwrap_or(0)
}

fn say(who: &str, what: &str) {
    let t = now_ms() % 100_000;
    println!("[{who} {:>3}.{:03}] {what}", t / 1000, t % 1000);
}
