//! Voice calls, private the same way messages are: no IP address reaches
//! the other person or any server, and no server learns who calls whom.
//!
//! Setting up a call goes through the conversation, as MLS-encrypted
//! [`CallSignal`]s. The audio doesn't: each side opens a *call line*, a
//! throwaway Nym client made for this call only (see
//! `Network::open_call`), and the two lines talk to each other directly
//! through the mixnet. Their addresses, and the call's key, travel only
//! inside the encrypted signals.
//!
//! ```text
//! Alice (calls)                                   Bob
//!   Offer{call, key, at}  ──── conversation ────►  rings
//!   opens line A                                    (answers) opens line B
//!   Line{A}               ──── conversation ────►  sends audio to A
//!   audio to B  ◄────────── B's address rides in its audio ──────────
//!   End{call, why}        ◄───────── either side ─────────►
//! ```
//!
//! What keeps the call private on the wire:
//! - A line sends one fixed-size packet every [`CALL_GAP`] from the moment
//!   it opens until it closes: before anyone answers, while either person
//!   speaks or is silent, and for a few random seconds after the call.
//!   Until there is someone to talk to, the packets go to the line itself.
//!   Neither the size nor the timing of packets ever depends on the speech.
//! - Opus runs at a constant bitrate, without silence suppression.
//! - Each packet is encrypted with a key that only the two people have
//!   (one direction each, from the offer's key), and carries the two
//!   chunks of audio before it as well, so a lost packet usually costs
//!   nothing.
//!
//! What it can't hide: a call line is a steady stream, so someone watching
//! your internet connection can tell that you are on a call, and someone
//! who watches both people's connections at once may be able to match the
//! two ends. Neither learns what is said, or (without the second) with whom.
//!
//! The audio itself goes through an [`AudioPipe`]: the app pushes what the
//! microphone hears and pulls what to play, as 48 kHz mono samples.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload as Aad};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use opus_codec::decoder::Decoder;
use opus_codec::encoder::Encoder;
use opus_codec::types::{Application, Bitrate, Channels, SampleRate, Signal};
use privmsg_transport::{MixAddress, Mux, Network, Transport, CALL_GAP};
use sha2::Sha256;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::time::{interval, sleep_until, Instant, MissedTickBehavior};
use zeroize::Zeroizing;

use crate::app::Node;
use crate::wire::{CallEnd, CallId, CallSignal};

/// Samples per second, everywhere in a call.
pub const RATE: u32 = 48_000;

/// One Opus frame: 20 ms.
const FRAME: usize = RATE as usize / 50;

/// Opus frames in one packet's worth ([`CALL_GAP`]) of audio.
const FRAMES: usize = (CALL_GAP.as_millis() / 20) as usize;

/// Samples in one packet's worth of audio.
pub const CHUNK: usize = FRAME * FRAMES;

/// Constant bitrate of the speech: wideband, clear voice. Every packet is
/// the same size whatever the bitrate; this only decides how much of it is
/// audio.
const BITRATE: i32 = 24_000;

/// Earlier chunks repeated in each packet.
const COPIES: usize = 2;

/// Size of every packet's plaintext. Three chunks of 24 kbit/s Opus and a
/// call-line address take about 1,100 bytes; the rest is zeros. With its
/// header and tag the packet still fits one Nym packet.
const BODY: usize = 1_396;

/// Bytes in front of the ciphertext: which of the sender's lines this is
/// (a call that reconnects gets a new one) and the packet's number on it.
/// Together they make the nonce, so no nonce repeats under the call's key.
const HEADER: usize = 8;

/// A packet on the wire: header, ciphertext, tag.
const PACKET: usize = HEADER + BODY + 16;

/// How long a call rings before it counts as unanswered.
const RING_FOR: Duration = Duration::from_secs(60);

/// How long the caller waits for an answer: the ringing, plus the time the
/// other side's line may take to come up once they answer.
const WAIT_FOR_ANSWER: Duration = Duration::from_secs(100);

/// An offer older (or newer, by a wrong clock) than this arrived too late
/// to answer: it shows as a missed call.
const LATE_OFFER: u64 = 90;

/// How long a line keeps sending after the call, chosen at random in this
/// range, so the end of the stream doesn't mark the end of the call.
const TAIL_SECS: std::ops::RangeInclusive<u32> = 3..=15;

/// No audio for this long while talking: the line is given up and a new
/// one opened (the connection may have stalled, or the phone changed
/// networks). Unless our own line still works (our test packets come
/// back): then the other side is likely setting up a new line, which
/// takes up to half a minute, and we wait for it up to [`AWAY_LIMIT`].
const SILENT_LIMIT: Duration = Duration::from_secs(15);
const AWAY_LIMIT: Duration = Duration::from_secs(60);

/// Quiet this long, and a line sends every tenth packet to itself
/// instead, to see whether it still works. (On the wire that looks the
/// same.)
const PROBE_AFTER: Duration = Duration::from_secs(3);

/// What counts as a poor line: fewer than half the packets getting
/// through, either way, measured over 5 s, for 8 s in a row. The line is
/// then replaced (a new one has new gateways), but not before it has been
/// talking for 20 s.
const QUALITY_WINDOW: Duration = Duration::from_secs(5);
const POOR_BELOW: f64 = 0.5;
const POOR_FOR: Duration = Duration::from_secs(8);
const POOR_LINE_AGE: Duration = Duration::from_secs(20);

/// New lines tried in a row, without hearing the other side in between,
/// before the call counts as lost.
const RECONNECTS: u32 = 3;

/// Room for the timing to wobble, held back on each side of the pipe on
/// top of the largest block the sound card has moved at once.
const JITTER: usize = RATE as usize / 50;

/// The largest block counted. Sound cards move 5–20 ms at a time; an
/// iPhone's microphone tap can hand over 100 ms or more.
const MAX_BLOCK: usize = 2 * CHUNK;

/// Most audio either side of the pipe holds; older is dropped.
const PIPE_LIMIT: usize = 4 * CHUNK + 2 * MAX_BLOCK;

/// Where the playout buffer starts before it has measured anything.
const START_DELAY_MS: f64 = 300.0;

/// Chunks the playout buffer remembers the timing of (10 s of audio): long
/// enough to see the path's wobble, short enough to follow it when it
/// changes.
const LATENESS_WINDOW: usize = 100;

/// No packet for this long is a stall; for [`FLUSH_MS`] after it, chunks
/// too late to play (the held-up backlog) aren't counted for the delay.
/// If the path really got slower they keep coming late, and count then.
const STALL_MS: f64 = 600.0;
const FLUSH_MS: f64 = 2_000.0;

/// Playing this much later than needed: skip ahead at once.
const CATCH_UP_MS: f64 = 400.0;

/// The most the playout waits. Now and then the mixnet lets a packet
/// through many seconds late; one that late can't be played anyway, so it
/// doesn't count for the delay.
const MAX_DELAY_MS: f64 = 2_000.0;

/// Packets in a row this much too late to play (3 s of them): the path got
/// slower for good, and the playout starts again on its timing.
const SLOWER_BY_MS: f64 = 1_000.0;
const SLOWER_RUN: u32 = 30;

/// Chunks the playout buffer aims to have in time (counting the copies
/// that later packets carry), and what it adds on top.
const ON_TIME: f64 = 0.98;
const MARGIN_MS: f64 = 40.0;

/// Audio between the app and a call: what the microphone heard, waiting to
/// be sent, and what came in, waiting to be played. Both are 48 kHz mono.
/// Clones share the same buffers.
///
/// Sound cards hand over and ask for audio in blocks of their own size, at
/// their own pace, while the call takes and gives 100 ms at a time on its
/// own clock. So each side keeps a small reserve: the largest block seen
/// plus [`JITTER`]. When a side runs dry anyway it starts again with a
/// little silence, rebuilding the reserve, so it doesn't run dry again on
/// every chunk; when it holds more than the timing explains, the oldest
/// audio is dropped, so a backlog never becomes lasting delay.
#[derive(Clone, Default)]
pub struct AudioPipe(Arc<Pipe>);

#[derive(Default)]
struct Pipe {
    mic: Mutex<Fifo>,
    speaker: Mutex<Fifo>,
    muted: AtomicBool,
}

#[derive(Default)]
struct Fifo {
    samples: VecDeque<f32>,
    /// The largest block the sound card has moved at once.
    block: usize,
    /// Whether the reserve is in place (not at the start, or after
    /// running dry).
    primed: bool,
    /// Times it ran dry, and dropped a backlog, this call.
    gaps: u32,
    drops: u32,
    /// Microphone: samples heard this call, and the loudest.
    heard: u64,
    loudest: f32,
}

impl Fifo {
    fn reserve(&self) -> usize {
        self.block + JITTER
    }

    fn saw_block(&mut self, n: usize) {
        self.block = self.block.max(n.min(MAX_BLOCK));
    }

    /// Drop the oldest audio beyond `keep`, if more than `most` is held.
    fn trim(&mut self, most: usize, keep: usize) {
        if self.samples.len() > most {
            let excess = self.samples.len() - keep;
            self.samples.drain(..excess);
            self.drops += 1;
        }
    }

    fn reset(&mut self) {
        self.samples.clear();
        self.primed = false;
        self.gaps = 0;
        self.drops = 0;
        self.heard = 0;
        self.loudest = 0.0;
    }
}

/// How the pipe has been doing this call (for the log, and to spot a
/// microphone that gives nothing).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PipeStats {
    /// Microphone samples heard this call, and the loudest of them (0 to 1).
    pub mic_heard: u64,
    pub mic_loudest: f32,
    /// Times the microphone ran dry before a chunk was due, or piled up.
    pub mic_gaps: u32,
    pub mic_drops: u32,
    /// Times the speaker ran dry, or piled up.
    pub speaker_gaps: u32,
    pub speaker_drops: u32,
}

impl AudioPipe {
    /// Microphone samples, as they come, in blocks of any size.
    pub fn push_mic(&self, samples: &[f32]) {
        let mut mic = lock(&self.0.mic);
        mic.saw_block(samples.len());
        mic.heard += samples.len() as u64;
        let loudest = samples.iter().fold(0.0f32, |m, s| m.max(s.abs()));
        if loudest.is_finite() {
            mic.loudest = mic.loudest.max(loudest);
        }
        mic.samples.extend(samples);
        let excess = mic.samples.len().saturating_sub(PIPE_LIMIT);
        mic.samples.drain(..excess);
    }

    /// Fill `out` with what to play next; silence where there is nothing.
    /// Ask for what the sound card wants right now, in one go: the pipe
    /// learns its block size from this.
    pub fn pull_speaker(&self, out: &mut [f32]) {
        let mut speaker = lock(&self.0.speaker);
        speaker.saw_block(out.len());
        let n = out.len().min(speaker.samples.len());
        for (o, s) in out.iter_mut().zip(speaker.samples.drain(..n)) {
            *o = s;
        }
        out[n..].fill(0.0);
        if n < out.len() && speaker.primed {
            speaker.primed = false;
            speaker.gaps += 1;
        }
    }

    pub fn set_muted(&self, muted: bool) {
        self.0.muted.store(muted, Ordering::Relaxed);
    }

    pub fn is_muted(&self) -> bool {
        self.0.muted.load(Ordering::Relaxed)
    }

    pub fn stats(&self) -> PipeStats {
        let mic = lock(&self.0.mic);
        let speaker = lock(&self.0.speaker);
        PipeStats {
            mic_heard: mic.heard,
            mic_loudest: mic.loudest,
            mic_gaps: mic.gaps,
            mic_drops: mic.drops,
            speaker_gaps: speaker.gaps,
            speaker_drops: speaker.drops,
        }
    }

    /// The next chunk of microphone audio (silence if muted, or until
    /// there is enough).
    fn take_mic(&self) -> Vec<f32> {
        let mut mic = lock(&self.0.mic);
        let reserve = mic.reserve();
        let mut chunk = Vec::with_capacity(CHUNK);
        if mic.primed && mic.samples.len() < CHUNK {
            mic.primed = false;
            mic.gaps += 1;
        }
        if mic.primed {
            chunk.extend(mic.samples.drain(..CHUNK));
            // A chunk taken late leaves up to a chunk extra, which the
            // next one (taken at once) takes; only more is a backlog.
            mic.trim(reserve + CHUNK + JITTER, reserve);
        } else {
            // Silence first, then what there is beyond the reserve: from
            // the next chunk on, whole chunks are there in time.
            let usable = mic.samples.len().saturating_sub(reserve).min(CHUNK);
            chunk.resize(CHUNK - usable, 0.0);
            chunk.extend(mic.samples.drain(..usable));
            mic.primed = usable > 0;
        }
        if self.is_muted() {
            chunk.fill(0.0);
        }
        chunk
    }

    fn drain_mic(&self) {
        let mut mic = lock(&self.0.mic);
        mic.samples.clear();
        mic.primed = false;
    }

    /// Decoded audio, a chunk at a time, for the speaker.
    fn play(&self, samples: &[f32]) {
        let mut speaker = lock(&self.0.speaker);
        let reserve = speaker.reserve();
        if speaker.primed {
            speaker.trim(2 * reserve, reserve);
        } else {
            // It ran dry (or is starting): a little silence in front, so
            // the next chunk arrives before this one has played out.
            let missing = reserve.saturating_sub(speaker.samples.len());
            speaker.samples.extend(std::iter::repeat_n(0.0, missing));
            speaker.primed = true;
        }
        speaker.samples.extend(samples);
        let excess = speaker.samples.len().saturating_sub(PIPE_LIMIT);
        speaker.samples.drain(..excess);
    }

    fn clear(&self) {
        lock(&self.0.mic).reset();
        lock(&self.0.speaker).reset();
        self.set_muted(false);
    }
}

/// Changes the sample rate of a stream of samples, a block at a time, by
/// straight-line interpolation: plenty for speech.
pub struct Resampler {
    /// Input samples per output sample.
    step: f64,
    /// Where the next output sample falls, in input samples from the start
    /// of the next block (-1 is the last sample of the block before).
    at: f64,
    last: f32,
}

impl Resampler {
    pub fn new(from: u32, to: u32) -> Self {
        Self {
            step: f64::from(from.max(1)) / f64::from(to.max(1)),
            at: 0.0,
            last: 0.0,
        }
    }

    /// Input samples per output sample.
    pub fn step(&self) -> f64 {
        self.step
    }

    /// Resample `input`, adding the result to `out`.
    pub fn run(&mut self, input: &[f32], out: &mut Vec<f32>) {
        if input.is_empty() {
            return;
        }
        if self.step == 1.0 {
            out.extend_from_slice(input);
            return;
        }
        let sample = |i: isize| {
            if i < 0 {
                self.last
            } else {
                input[i as usize]
            }
        };
        let end = (input.len() - 1) as f64;
        while self.at < end {
            let i = self.at.floor();
            let frac = (self.at - i) as f32;
            let (a, b) = (sample(i as isize), sample(i as isize + 1));
            out.push(a + (b - a) * frac);
            self.at += self.step;
        }
        self.at -= input.len() as f64;
        self.last = input[input.len() - 1];
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Cleans up microphone audio before it is sent: echo cancelling, on a
/// computer (a phone does its own). Gets everything played, and every
/// chunk of microphone audio, in order.
pub trait Processor: Send {
    fn render(&mut self, played: &[f32]);
    fn capture(&mut self, mic: &mut [f32]);
}

/// Makes a [`Processor`] for each call.
pub type MakeProcessor = Arc<dyn Fn() -> Box<dyn Processor> + Send + Sync>;

/// Where a call is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallState {
    /// We called; their phone is ringing (or our line is still coming up).
    Calling,
    /// They are calling us.
    Ringing,
    /// We answered; the line is coming up.
    Connecting,
    /// Both are talking.
    Talking,
}

/// The call, for the screen.
#[derive(Clone, Debug, PartialEq)]
pub struct CallInfo {
    pub contact: String,
    pub outgoing: bool,
    pub state: CallState,
    /// Time spent talking so far.
    pub talking: Duration,
    pub muted: bool,
}

/// What the app should show or do because of a call.
#[derive(Debug, PartialEq)]
pub enum CallUpdate {
    /// Someone is calling: ring.
    Ringing { contact: String },
    /// The talking starts: open the microphone and speaker.
    Talking { contact: String },
    /// The connection dropped; a new private line is being set up. The
    /// call goes on.
    Reconnecting { contact: String },
    /// The call is over: close the microphone and speaker. `note` says how
    /// it ended ("Call · 3:12", "Missed call", "Busy"...).
    Ended { contact: String, note: String },
    /// A call that never rang, because it came too late or while busy.
    Missed { contact: String },
}

/// The one call there can be at a time, and the rules for it. The app
/// feeds it the call signals from the conversation (`Event::Call`) and what
/// its call line reports ([`Calls::next`]), and asks it to start, answer
/// and hang up.
pub struct Calls {
    audio: AudioPipe,
    processor: Option<MakeProcessor>,
    current: Option<Call>,
}

struct Call {
    id: CallId,
    contact: String,
    outgoing: bool,
    state: CallState,
    key: Zeroizing<[u8; 32]>,
    /// The other side's call line, once we know it.
    peer: Option<MixAddress>,
    line: Option<LineHandle>,
    /// Until when an unanswered call keeps ringing.
    ring_until: Instant,
    talking_since: Option<Instant>,
    /// New lines opened since the other side was last heard.
    reconnects: u32,
    /// Lines we have opened for this call: each new one is numbered on.
    lines: u32,
}

struct LineHandle {
    commands: UnboundedSender<LineCommand>,
    news: UnboundedReceiver<LineNews>,
}

impl Calls {
    /// `processor` makes the echo canceller for each call, if the app
    /// doesn't have one of its own.
    pub fn new(audio: AudioPipe, processor: Option<MakeProcessor>) -> Self {
        Self {
            audio,
            processor,
            current: None,
        }
    }

    pub fn audio(&self) -> &AudioPipe {
        &self.audio
    }

    pub fn info(&self) -> Option<CallInfo> {
        self.current.as_ref().map(|c| CallInfo {
            contact: c.contact.clone(),
            outgoing: c.outgoing,
            state: c.state,
            talking: c.talking_since.map_or(Duration::ZERO, |t| t.elapsed()),
            muted: self.audio.is_muted(),
        })
    }

    pub fn is_busy(&self) -> bool {
        self.current.is_some()
    }

    pub fn set_muted(&self, muted: bool) {
        self.audio.set_muted(muted);
    }

    /// Call `name`: open our call line and ring them.
    pub async fn start<N: Network>(
        &mut self,
        node: &mut Node,
        mux: &mut Mux<N>,
        name: &str,
    ) -> Result<()> {
        if let Some(call) = &self.current {
            bail!("already in a call with {}", call.contact);
        }
        node.contact(name)?;
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *key);
        let offer = CallSignal::Offer {
            call: id,
            key: *key,
            at: unix_now(),
        };
        node.send_call(mux, name, offer)
            .await
            .context("could not ring them")?;
        let line = self.spawn_line(mux, &id, &key, true, 0);
        self.current = Some(Call {
            id,
            contact: name.to_string(),
            outgoing: true,
            state: CallState::Calling,
            key,
            peer: None,
            line: Some(line),
            ring_until: Instant::now() + WAIT_FOR_ANSWER,
            talking_since: None,
            reconnects: 0,
            lines: 1,
        });
        Ok(())
    }

    /// Answer the call that is ringing: open our call line. The caller hears
    /// we answered when it is up (a few seconds to half a minute).
    pub fn accept<N: Network>(&mut self, mux: &Mux<N>) -> Result<()> {
        let processor = self.processor.clone();
        let audio = self.audio.clone();
        let call = match &mut self.current {
            Some(call) if call.state == CallState::Ringing => call,
            _ => bail!("no call is ringing"),
        };
        let line = LineHandle::spawn(
            mux.open_call(),
            Directions::new(&call.id, &call.key, false, call.lines),
            audio,
            processor,
        );
        call.lines += 1;
        if let Some(peer) = &call.peer {
            line.send(LineCommand::Peer(peer.clone()));
        }
        call.line = Some(line);
        call.state = CallState::Connecting;
        Ok(())
    }

    /// Hang up, decline, or stop calling. Returns what to show.
    pub async fn hang_up<N: Network>(
        &mut self,
        node: &mut Node,
        mux: &mut Mux<N>,
    ) -> Option<CallUpdate> {
        let call = self.current.as_ref()?;
        let why = match (call.state, call.outgoing) {
            (CallState::Ringing, false) => CallEnd::Declined,
            _ => CallEnd::HungUp,
        };
        let (id, contact) = (call.id, call.contact.clone());
        if let Err(e) = node
            .send_call(mux, &contact, CallSignal::End { call: id, why })
            .await
        {
            tracing::warn!("could not tell {contact} the call ended: {e:#}");
        }
        let note = match why {
            CallEnd::Declined => "Declined call".to_string(),
            _ => self.talked().unwrap_or_else(|| "Call cancelled".into()),
        };
        Some(self.finish(node, note, false))
    }

    /// Act on a call signal from the conversation.
    pub async fn on_signal<N: Network>(
        &mut self,
        node: &mut Node,
        mux: &mut Mux<N>,
        contact: &str,
        signal: CallSignal,
    ) -> Option<CallUpdate> {
        match signal {
            CallSignal::Offer { call, key, at } => {
                let now = unix_now();
                let late =
                    now.saturating_sub(at) > LATE_OFFER || at.saturating_sub(now) > LATE_OFFER;
                if late || self.current.is_some() {
                    if !late {
                        let busy = CallSignal::End {
                            call,
                            why: CallEnd::Busy,
                        };
                        if let Err(e) = node.send_call(mux, contact, busy).await {
                            tracing::warn!("could not tell {contact} we are busy: {e:#}");
                        }
                    }
                    note(node, contact, false, "Missed call", true);
                    return Some(CallUpdate::Missed {
                        contact: contact.to_string(),
                    });
                }
                self.current = Some(Call {
                    id: call,
                    contact: contact.to_string(),
                    outgoing: false,
                    state: CallState::Ringing,
                    key: Zeroizing::new(key),
                    peer: None,
                    line: None,
                    ring_until: Instant::now() + RING_FOR,
                    talking_since: None,
                    reconnects: 0,
                    lines: 0,
                });
                Some(CallUpdate::Ringing {
                    contact: contact.to_string(),
                })
            }
            CallSignal::Line { call, address } => {
                let current = self.current_for(contact, &call)?;
                let address = MixAddress(address);
                if let Some(line) = &current.line {
                    line.send(LineCommand::Peer(address.clone()));
                }
                current.peer = Some(address);
                // From the callee, a line means they answered.
                if current.outgoing {
                    return self.talking();
                }
                None
            }
            CallSignal::End { call, why } => {
                let current = self.current_for(contact, &call)?;
                let (outgoing, state) = (current.outgoing, current.state);
                let note = match (why, outgoing, state) {
                    (_, _, CallState::Talking) => self.talked().expect("talking"),
                    (_, false, _) => "Missed call".into(),
                    (CallEnd::Declined, true, _) => "Declined".into(),
                    (CallEnd::Busy, true, _) => "Busy".into(),
                    (CallEnd::NoAnswer, true, _) => "No answer".into(),
                    (CallEnd::Failed, _, _) => "Call failed".into(),
                    (CallEnd::HungUp, true, _) => "Call cancelled".into(),
                };
                let missed = !outgoing && state == CallState::Ringing;
                Some(self.finish(node, note, missed))
            }
        }
    }

    /// The next thing our call line reports. Never resolves without a
    /// line. Cancel-safe.
    pub async fn next(&mut self) -> LineNews {
        match self.current.as_mut().and_then(|c| c.line.as_mut()) {
            Some(line) => line.news.recv().await.unwrap_or(LineNews::Closed),
            None => std::future::pending().await,
        }
    }

    /// Act on what the call line reported.
    pub async fn on_news<N: Network>(
        &mut self,
        node: &mut Node,
        mux: &mut Mux<N>,
        news: LineNews,
    ) -> Option<CallUpdate> {
        let call = self.current.as_mut()?;
        match news {
            LineNews::Ready(address) => {
                let line = CallSignal::Line {
                    call: call.id,
                    address: address.0,
                };
                let contact = call.contact.clone();
                if let Err(e) = node.send_call(mux, &contact, line).await {
                    tracing::warn!("could not send the call line to {contact}: {e:#}");
                }
                if self.current.as_ref().is_some_and(|c| !c.outgoing) {
                    // We answered; our audio goes out as soon as we know
                    // where to.
                    return self.talking();
                }
                None
            }
            LineNews::Heard(address) => {
                // Their audio may come before their signal does.
                call.peer = Some(address);
                call.reconnects = 0;
                if call.outgoing {
                    return self.talking();
                }
                None
            }
            LineNews::Failed(e)
                if call.state == CallState::Talking && call.reconnects < RECONNECTS =>
            {
                tracing::warn!("call line failed ({e}); opening a new one");
                call.reconnects += 1;
                let line = LineHandle::spawn(
                    mux.open_call(),
                    Directions::new(&call.id, &call.key, call.outgoing, call.lines),
                    self.audio.clone(),
                    self.processor.clone(),
                );
                call.lines += 1;
                if let Some(peer) = &call.peer {
                    line.send(LineCommand::Peer(peer.clone()));
                }
                line.send(LineCommand::Talk);
                if let Some(old) = call.line.replace(line) {
                    old.send(LineCommand::Stop);
                }
                Some(CallUpdate::Reconnecting {
                    contact: call.contact.clone(),
                })
            }
            LineNews::Failed(e) => {
                tracing::warn!("call line failed: {e}");
                let (id, contact) = (call.id, call.contact.clone());
                let end = CallSignal::End {
                    call: id,
                    why: CallEnd::Failed,
                };
                if let Err(e) = node.send_call(mux, &contact, end).await {
                    tracing::warn!("could not tell {contact} the call failed: {e:#}");
                }
                let note = self.talked().unwrap_or_else(|| "Call failed".into());
                Some(self.finish(node, note, false))
            }
            LineNews::Closed => {
                call.line = None;
                None
            }
        }
    }

    /// When [`check`](Self::check) should next run, if a call rings.
    pub fn deadline(&self) -> Option<Instant> {
        self.current
            .as_ref()
            .filter(|c| matches!(c.state, CallState::Calling | CallState::Ringing))
            .map(|c| c.ring_until)
    }

    /// End a call that has rung too long.
    pub async fn check<N: Network>(
        &mut self,
        node: &mut Node,
        mux: &mut Mux<N>,
    ) -> Option<CallUpdate> {
        let call = self.current.as_ref()?;
        if Instant::now() < call.ring_until
            || !matches!(call.state, CallState::Calling | CallState::Ringing)
        {
            return None;
        }
        if call.outgoing {
            let (id, contact) = (call.id, call.contact.clone());
            let end = CallSignal::End {
                call: id,
                why: CallEnd::NoAnswer,
            };
            if let Err(e) = node.send_call(mux, &contact, end).await {
                tracing::warn!("could not tell {contact} the call stopped: {e:#}");
            }
            Some(self.finish(node, "No answer".into(), false))
        } else {
            Some(self.finish(node, "Missed call".into(), true))
        }
    }

    /// The contact left (or was removed) while in a call with us.
    pub fn forget(&mut self, node: &mut Node, contact: &str) -> Option<CallUpdate> {
        if self.current.as_ref()?.contact != contact {
            return None;
        }
        let update = self.finish(node, String::new(), false);
        Some(update)
    }

    fn current_for(&mut self, contact: &str, id: &CallId) -> Option<&mut Call> {
        self.current
            .as_mut()
            .filter(|c| c.contact == contact && c.id == *id)
    }

    /// The call starts talking (once).
    fn talking(&mut self) -> Option<CallUpdate> {
        let call = self.current.as_mut()?;
        if call.state == CallState::Talking {
            return None;
        }
        call.state = CallState::Talking;
        call.talking_since = Some(Instant::now());
        if let Some(line) = &call.line {
            line.send(LineCommand::Talk);
        }
        Some(CallUpdate::Talking {
            contact: call.contact.clone(),
        })
    }

    /// "Call · m:ss", if the call got to talking.
    fn talked(&self) -> Option<String> {
        let since = self.current.as_ref()?.talking_since?;
        let secs = since.elapsed().as_secs();
        Some(format!("Call · {}:{:02}", secs / 60, secs % 60))
    }

    /// End the call here: stop the line (it keeps sending a little longer
    /// by itself) and note it in the chat, unless `note` is empty.
    fn finish(&mut self, node: &mut Node, note_text: String, missed: bool) -> CallUpdate {
        let call = self.current.take().expect("a call to finish");
        if let Some(line) = &call.line {
            line.send(LineCommand::Stop);
        }
        self.audio.clear();
        if !note_text.is_empty() {
            note(node, &call.contact, call.outgoing, &note_text, missed);
        }
        CallUpdate::Ended {
            contact: call.contact,
            note: note_text,
        }
    }

    fn spawn_line<N: Network>(
        &self,
        mux: &Mux<N>,
        id: &CallId,
        key: &[u8; 32],
        caller: bool,
        line: u32,
    ) -> LineHandle {
        LineHandle::spawn(
            mux.open_call(),
            Directions::new(id, key, caller, line),
            self.audio.clone(),
            self.processor.clone(),
        )
    }
}

fn note(node: &mut Node, contact: &str, outgoing: bool, text: &str, unread: bool) {
    if let Err(e) = node.note_call(contact, outgoing, text, unread) {
        tracing::warn!("could not note the call in the chat: {e:#}");
    }
}

/// What a call line reports.
#[derive(Debug)]
pub enum LineNews {
    /// Up, at this address.
    Ready(MixAddress),
    /// Audio from the other side arrived (from its line at this address).
    Heard(MixAddress),
    /// Could not be made, or died.
    Failed(String),
    /// Closed after the call.
    Closed,
}

#[derive(Debug)]
enum LineCommand {
    /// Where the other side's line is.
    Peer(MixAddress),
    /// Both sides are in: send and play audio.
    Talk,
    /// The call is over.
    Stop,
}

impl LineHandle {
    fn spawn<E, F>(
        opening: F,
        keys: Directions,
        audio: AudioPipe,
        processor: Option<MakeProcessor>,
    ) -> Self
    where
        E: Transport + Send + 'static,
        F: Future<Output = Result<E>> + Send + 'static,
    {
        let (commands, command_rx) = unbounded_channel();
        let (news_tx, news) = unbounded_channel();
        let processor = processor.map(|make| make());
        tokio::spawn(async move {
            let ended = run_line(opening, keys, audio, processor, command_rx, &news_tx).await;
            let _ = news_tx.send(match ended {
                Ok(()) => LineNews::Closed,
                Err(e) => LineNews::Failed(format!("{e:#}")),
            });
        });
        Self { commands, news }
    }

    fn send(&self, command: LineCommand) {
        // The line may already have ended by itself.
        let _ = self.commands.send(command);
    }
}

/// The call's two keys: one for each direction, from the offer's key; and
/// which of our lines this is.
struct Directions {
    call: CallId,
    send: Zeroizing<[u8; 32]>,
    receive: Zeroizing<[u8; 32]>,
    line: u32,
}

impl Directions {
    fn new(call: &CallId, key: &[u8; 32], caller: bool, line: u32) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(call), key);
        let mut from_caller = Zeroizing::new([0u8; 32]);
        let mut from_callee = Zeroizing::new([0u8; 32]);
        hk.expand(b"privmsg call v1 from caller", &mut *from_caller)
            .expect("32 bytes is a valid length");
        hk.expand(b"privmsg call v1 from callee", &mut *from_callee)
            .expect("32 bytes is a valid length");
        let (send, receive) = if caller {
            (from_caller, from_callee)
        } else {
            (from_callee, from_caller)
        };
        Self {
            call: *call,
            send,
            receive,
            line,
        }
    }
}

/// Packet `seq` of line `line` as an AEAD nonce. Each direction has its own
/// key, so the pair only has to be unique per direction: each side numbers
/// its lines, and the packets on each line.
fn nonce(line: u32, seq: u32) -> Nonce {
    let mut n = [0u8; 12];
    n[4..8].copy_from_slice(&line.to_be_bytes());
    n[8..].copy_from_slice(&seq.to_be_bytes());
    n.into()
}

/// What a packet from the other side carried.
struct Opened {
    /// Which of their lines sent it.
    line: u32,
    /// That line's address.
    from: MixAddress,
    /// How much of our audio it is getting, in percent (once it knows).
    heard: Option<u8>,
    chunks: Vec<Chunk>,
}

/// One chunk of audio: its number and its Opus frames.
type Chunk = (u32, Vec<Vec<u8>>);

/// Seal a packet: `seq`, our line's address (so the other side can answer
/// before our signal reaches it), how much of their audio we get (percent,
/// or 255 for not known yet) and `chunks`, newest first.
fn seal(
    keys: &Directions,
    seq: u32,
    from: &MixAddress,
    heard: u8,
    chunks: &[Chunk],
) -> Result<Vec<u8>> {
    let mut body = Vec::with_capacity(BODY);
    let address = from.0.as_bytes();
    let address = if address.len() <= u8::MAX as usize {
        address
    } else {
        &[]
    };
    body.push(address.len() as u8);
    body.extend_from_slice(address);
    body.push(heard);
    let count_at = body.len();
    body.push(0);
    for (n, frames) in chunks {
        let size = 4 + 1 + frames.iter().map(|f| 1 + f.len()).sum::<usize>();
        if body.len() + size > BODY {
            break; // older copies make way
        }
        body.extend_from_slice(&n.to_be_bytes());
        body.push(frames.len() as u8);
        for frame in frames {
            body.push(frame.len() as u8);
            body.extend_from_slice(frame);
        }
        body[count_at] += 1;
    }
    body.resize(BODY, 0);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*keys.send));
    let sealed = cipher
        .encrypt(
            &nonce(keys.line, seq),
            Aad {
                msg: &body,
                aad: &keys.call,
            },
        )
        .map_err(|_| anyhow!("could not encrypt audio"))?;
    let mut packet = Vec::with_capacity(PACKET);
    packet.extend_from_slice(&keys.line.to_be_bytes());
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&sealed);
    Ok(packet)
}

/// Open a packet from the other side. `None` for anything else (our own
/// filler coming back, or junk).
fn open(keys: &Directions, packet: &[u8]) -> Option<Opened> {
    if packet.len() != PACKET {
        return None;
    }
    let line = u32::from_be_bytes(packet[..4].try_into().ok()?);
    let seq = u32::from_be_bytes(packet[4..HEADER].try_into().ok()?);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*keys.receive));
    let body = cipher
        .decrypt(
            &nonce(line, seq),
            Aad {
                msg: &packet[HEADER..],
                aad: &keys.call,
            },
        )
        .ok()?;
    let mut r = Reader(&body);
    let len = r.byte()? as usize;
    let address = r.take(len)?;
    let address = MixAddress(String::from_utf8(address.to_vec()).ok()?);
    let heard = r.byte()?;
    let mut chunks = Vec::new();
    for _ in 0..r.byte()? {
        let n = u32::from_be_bytes(r.take(4)?.try_into().ok()?);
        let mut frames = Vec::new();
        for _ in 0..r.byte()? {
            let len = r.byte()? as usize;
            frames.push(r.take(len)?.to_vec());
        }
        chunks.push((n, frames));
    }
    Some(Opened {
        line,
        from: address,
        heard: (heard <= 100).then_some(heard),
        chunks,
    })
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.0.len() {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }
}

/// A packet of random bytes, the size of a real one: what a line sends to
/// itself while there is no one to talk to.
fn filler() -> Vec<u8> {
    let mut packet = vec![0u8; PACKET];
    OsRng.fill_bytes(&mut packet);
    packet
}

fn encoder() -> Result<Encoder> {
    let mut encoder = Encoder::new(SampleRate::Hz48000, Channels::Mono, Application::Voip)
        .map_err(|e| anyhow!("Opus encoder: {e}"))?;
    let set = |r: opus_codec::error::Result<()>| r.map_err(|e| anyhow!("Opus encoder: {e}"));
    set(encoder.set_bitrate(Bitrate::Custom(BITRATE)))?;
    // Constant bitrate and no silence suppression: nothing about the
    // speech may change what goes on the wire.
    set(encoder.set_vbr(false))?;
    set(encoder.set_dtx(false))?;
    set(encoder.set_inband_fec(false))?;
    set(encoder.set_signal(Signal::Voice))?;
    Ok(encoder)
}

fn decoder() -> Result<Decoder> {
    Decoder::new(SampleRate::Hz48000, Channels::Mono).map_err(|e| anyhow!("Opus decoder: {e}"))
}

/// Encode one chunk of audio as Opus frames.
fn encode(encoder: &mut Encoder, pcm: &[f32]) -> Result<Vec<Vec<u8>>> {
    pcm.chunks(FRAME)
        .map(|frame| {
            let mut out = [0u8; 255];
            let n = encoder
                .encode_float(frame, &mut out)
                .map_err(|e| anyhow!("Opus encoder: {e}"))?;
            Ok(out[..n].to_vec())
        })
        .collect()
}

/// The call line itself: opens, then sends one packet every [`CALL_GAP`]
/// until told to stop and a random tail has passed, receiving and playing
/// the other side's audio meanwhile.
async fn run_line<E, F>(
    opening: F,
    keys: Directions,
    audio: AudioPipe,
    mut processor: Option<Box<dyn Processor>>,
    mut commands: UnboundedReceiver<LineCommand>,
    news: &UnboundedSender<LineNews>,
) -> Result<()>
where
    E: Transport + Send + 'static,
    F: Future<Output = Result<E>> + Send + 'static,
{
    tokio::pin!(opening);
    let mut early = Vec::new();
    let mut line = loop {
        tokio::select! {
            line = &mut opening => break line?,
            command = commands.recv() => match command {
                None | Some(LineCommand::Stop) => return Ok(()),
                Some(command) => early.push(command),
            },
        }
    };
    let me = line.address();
    let _ = news.send(LineNews::Ready(me.clone()));

    let mut encoder = encoder()?;
    let mut playout = Playout::new(decoder()?);
    let mut peer = None;
    let mut talking = false;
    let mut seq: u32 = 0;
    let mut recent: VecDeque<Chunk> = VecDeque::with_capacity(COPIES + 1);
    let mut stop_at: Option<Instant> = None;
    // The other side's line we last heard from (each of their lines is
    // numbered), and when we last heard it (or the talking began).
    let mut their_line: Option<u32> = None;
    let mut last_heard = Instant::now();
    // How the line is doing: when their packets came (their current line,
    // the last few seconds), since when we have heard that line, what they
    // last said they get of ours, since when either has been poor, when the
    // talking began on this line, and when a test packet to ourselves last
    // came back.
    let mut arrivals: VecDeque<Instant> = VecDeque::new();
    let mut heard_since: Option<Instant> = None;
    let mut reported: Option<(u8, Instant)> = None;
    let mut poor_since: Option<Instant> = None;
    let mut talk_began: Option<Instant> = None;
    let mut echoed: Option<Instant> = None;
    for command in early {
        apply(command, &mut peer, &mut talking, &mut stop_at);
    }

    // The send clock keeps to its grid. After a stall (the connection held
    // up a send) the missed ticks are skipped, not sent in a rush: that
    // audio would come too late to play. Packet numbers follow the clock
    // all the same, so the other side sees a gap, not a slower stream.
    let started = Instant::now();
    let mut tick = interval(CALL_GAP);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut report = interval(Duration::from_secs(10));
    let (mut arrived_since, mut sent_since) = (0u32, 0u32);
    loop {
        let due = playout.due();
        tokio::select! {
            _ = tick.tick() => {
                if stop_at.is_some_and(|at| Instant::now() >= at) {
                    break;
                }
                let now = Instant::now();
                if talking && talk_began.is_none() {
                    talk_began = Some(now);
                }
                while arrivals.front().is_some_and(|t| now - *t > QUALITY_WINDOW) {
                    arrivals.pop_front();
                }
                // What we get of theirs, once there has been time to tell.
                let getting = heard_since
                    .filter(|since| now - *since >= QUALITY_WINDOW)
                    .map(|_| arrivals.len() as f64 / (QUALITY_WINDOW.as_millis() / CALL_GAP.as_millis()) as f64);
                let quiet = last_heard.elapsed() > PROBE_AFTER;
                let probe = quiet && seq.is_multiple_of(10);
                let (to, packet) = match (&peer, talking && stop_at.is_none() && !probe) {
                    (Some(peer), true) => {
                        let mut pcm = audio.take_mic();
                        if let Some(p) = processor.as_mut() {
                            p.capture(&mut pcm);
                        }
                        let on_clock = started.elapsed().as_millis() / CALL_GAP.as_millis();
                        seq = seq.max(u32::try_from(on_clock).unwrap_or(u32::MAX));
                        recent.push_front((seq, encode(&mut encoder, &pcm)?));
                        recent.truncate(COPIES + 1);
                        let heard = getting.map_or(u8::MAX, |g| (g * 100.0).round().min(100.0) as u8);
                        let packet = seal(&keys, seq, &me, heard, recent.make_contiguous())?;
                        seq = seq.saturating_add(1);
                        (peer.clone(), packet)
                    }
                    _ if probe && talking && stop_at.is_none() => {
                        // This tick's audio is lost; the number moves on.
                        audio.take_mic();
                        seq = seq.saturating_add(1);
                        (me.clone(), filler())
                    }
                    _ => {
                        audio.drain_mic();
                        (me.clone(), filler())
                    }
                };
                sent_since += 1;
                if let Err(e) = line.send(&to, &packet).await {
                    tracing::debug!("call packet not sent: {e:#}");
                }
                if !line.is_alive() {
                    line.close().await;
                    bail!("the call line's connection died");
                }
                if !talking || stop_at.is_some() {
                    continue;
                }
                let silent = last_heard.elapsed();
                // Our own line works if its test packets come back.
                let works = echoed.is_some_and(|at| at.elapsed() < 2 * PROBE_AFTER);
                if silent > SILENT_LIMIT && (!works || silent > AWAY_LIMIT) {
                    line.close().await;
                    bail!("nothing heard from the other side for {} s", silent.as_secs());
                }
                let theirs = reported
                    .filter(|(_, at)| at.elapsed() < QUALITY_WINDOW)
                    .map(|(p, _)| f64::from(p) / 100.0);
                let worst = getting.into_iter().chain(theirs).fold(1.0f64, f64::min);
                if worst < POOR_BELOW && !quiet {
                    let since = *poor_since.get_or_insert(now);
                    let old = talk_began.is_some_and(|at| now - at > POOR_LINE_AGE);
                    if now - since > POOR_FOR && old {
                        line.close().await;
                        bail!(
                            "poor connection: only {:.0}% of the audio getting through",
                            worst * 100.0
                        );
                    }
                } else {
                    poor_since = None;
                }
            }
            arrived = line.recv() => {
                let arrived = arrived.context("the call line stopped receiving")?;
                if stop_at.is_some() {
                    continue;
                }
                let Some(Opened { line: theirs, from, heard, chunks }) = open(&keys, &arrived.payload) else {
                    // Our own filler, back from the mixnet: our line works.
                    echoed = Some(Instant::now());
                    continue;
                };
                // Only the other side has the key, so the address inside is
                // theirs. A newer line of theirs replaced the old one: follow
                // it, and start its audio afresh (new numbers, new timing).
                // Stragglers from an older one are too late to matter.
                match their_line {
                    Some(known) if theirs < known => continue,
                    Some(known) if theirs == known => {}
                    known => {
                        if known.is_some() {
                            playout = Playout::new(decoder()?);
                        }
                        their_line = Some(theirs);
                        peer = Some(from.clone());
                        arrivals.clear();
                        heard_since = Some(Instant::now());
                        poor_since = None;
                        let _ = news.send(LineNews::Heard(from));
                    }
                }
                last_heard = Instant::now();
                arrivals.push_back(last_heard);
                if let Some(heard) = heard {
                    reported = Some((heard, last_heard));
                }
                arrived_since += 1;
                if talking {
                    playout.arrive(chunks);
                }
            }
            _ = sleep_until(due.unwrap_or_else(Instant::now)), if due.is_some() && talking => {
                let pcm = playout.play()?;
                if let Some(p) = processor.as_mut() {
                    p.render(&pcm);
                }
                audio.play(&pcm);
            }
            _ = report.tick(), if talking => {
                let pipe = audio.stats();
                tracing::info!(
                    "call: in 10 s sent {sent_since}, got {arrived_since} packets; playing \
                     {:.0} ms after the fastest (98% of chunks within {:.0} ms); {} of {} \
                     chunks concealed; microphone ran dry {} / piled up {} times, speaker {} / {}",
                    playout.delay - playout.fastest(),
                    playout.on_time() - playout.fastest(),
                    playout.concealed,
                    playout.played,
                    pipe.mic_gaps,
                    pipe.mic_drops,
                    pipe.speaker_gaps,
                    pipe.speaker_drops,
                );
                arrived_since = 0;
                sent_since = 0;
            }
            command = commands.recv() => match command {
                Some(command) => {
                    if matches!(command, LineCommand::Talk) && !talking {
                        last_heard = Instant::now();
                    }
                    apply(command, &mut peer, &mut talking, &mut stop_at)
                }
                None => {
                    stop_at.get_or_insert_with(tail);
                }
            },
        }
    }
    line.close().await;
    Ok(())
}

fn apply(
    command: LineCommand,
    peer: &mut Option<MixAddress>,
    talking: &mut bool,
    stop_at: &mut Option<Instant>,
) {
    match command {
        LineCommand::Peer(address) => *peer = Some(address),
        LineCommand::Talk => *talking = true,
        LineCommand::Stop => {
            stop_at.get_or_insert_with(tail);
        }
    }
}

/// When a stopped line closes: a few random seconds from now.
fn tail() -> Instant {
    let span = TAIL_SECS.end() - TAIL_SECS.start() + 1;
    let secs = TAIL_SECS.start() + OsRng.next_u32() % span;
    Instant::now() + Duration::from_secs(secs.into())
}

/// The other side's audio, waiting to be played: it comes in out of order
/// and with varying delay, and plays in order at a steady pace. It waits
/// long enough for [`ON_TIME`] of the chunks, measured over the last ten
/// seconds, to be there in time, from their own packet or a copy in a later
/// one; it covers the rest with Opus's own guess of the missing sound.
struct Playout {
    decoder: Decoder,
    chunks: BTreeMap<u32, Vec<Vec<u8>>>,
    /// The next chunk to play.
    next: Option<u32>,
    /// The first packet: when it came (ms after `start`) and its number.
    anchor: Option<(f64, u32)>,
    start: Instant,
    /// Chunks seen lately (in any packet), so each is timed once: when the
    /// first copy came.
    seen: BTreeSet<u32>,
    /// How late recent chunks were compared to the first packet, in ms.
    lateness: VecDeque<f64>,
    /// How long after its slot (by the first packet's timing) a chunk plays.
    delay: f64,
    adjusted_at: f64,
    /// When the last packet came, and, after a stall, since when packets
    /// have been coming in too late to play (a held-up backlog let go).
    last_arrival: Option<f64>,
    flushing_since: Option<f64>,
    /// Packets in a row that came far too late to play.
    late_run: u32,
    /// Chunks played, and of those, guessed because they never came.
    played: u32,
    concealed: u32,
}

impl Playout {
    fn new(decoder: Decoder) -> Self {
        Self {
            decoder,
            chunks: BTreeMap::new(),
            next: None,
            anchor: None,
            start: Instant::now(),
            seen: BTreeSet::new(),
            lateness: VecDeque::with_capacity(LATENESS_WINDOW),
            delay: START_DELAY_MS,
            adjusted_at: 0.0,
            last_arrival: None,
            flushing_since: None,
            late_run: 0,
            played: 0,
            concealed: 0,
        }
    }

    /// Forget the timing, to start again from the next packet. (The
    /// decoder, and the counts, carry on.)
    fn restart(&mut self) {
        self.chunks.clear();
        self.next = None;
        self.anchor = None;
        self.start = Instant::now();
        self.seen.clear();
        self.lateness.clear();
        self.delay = START_DELAY_MS;
        self.adjusted_at = 0.0;
        self.last_arrival = None;
        self.flushing_since = None;
        self.late_run = 0;
    }

    fn now(&self) -> f64 {
        self.start.elapsed().as_secs_f64() * 1000.0
    }

    /// Where chunk `n` belongs on the timeline, in ms after `start`.
    fn slot(&self, n: u32) -> Option<f64> {
        let (at, first) = self.anchor?;
        Some(at + (f64::from(n) - f64::from(first)) * CALL_GAP.as_millis() as f64)
    }

    fn arrive(&mut self, chunks: Vec<Chunk>) {
        let Some(&(newest, _)) = chunks.first() else {
            return;
        };
        let now = self.now();
        let gap = CALL_GAP.as_millis() as f64;
        if let Some(slot) = self.slot(newest) {
            let late = now - slot;
            if late > self.delay + SLOWER_BY_MS {
                self.late_run += 1;
            } else if late <= self.delay + gap {
                self.late_run = 0;
            }
            if self.late_run >= SLOWER_RUN {
                tracing::info!("call: the path got slower; playing on its new timing");
                self.restart();
            }
        }
        let now = self.now();
        let (_, first) = *self.anchor.get_or_insert((now, newest));
        let next = *self.next.get_or_insert(newest);
        // After a stall, what was held up comes all at once, far too late.
        // That says nothing about how late packets are from now on, so it
        // isn't counted, unless it goes on (the path really got slower).
        if self.last_arrival.is_some_and(|at| now - at > STALL_MS) {
            self.flushing_since = Some(now);
        }
        self.last_arrival = Some(now);
        if self
            .flushing_since
            .is_some_and(|since| now - since > FLUSH_MS)
        {
            self.flushing_since = None;
        }
        for (n, frames) in chunks {
            if n >= first && self.seen.insert(n) {
                let late = now - self.slot(n).expect("anchored");
                // Held up by the stall: not counted.
                let held_up = self.flushing_since.is_some() && late > self.delay + 2.0 * gap;
                // Later than the playout ever waits: can't be played.
                let hopeless =
                    !self.lateness.is_empty() && late > self.fastest() + MAX_DELAY_MS + gap;
                if !held_up && !hopeless {
                    if self.lateness.len() == LATENESS_WINDOW {
                        self.lateness.pop_front();
                    }
                    self.lateness.push_back(late);
                }
            }
            if n >= next {
                self.chunks.entry(n).or_insert(frames);
            }
        }
        // Copies come at most a few packets after their own.
        let floor = newest.saturating_sub(64);
        self.seen = self.seen.split_off(&floor);
    }

    /// When the next chunk is due, once anything has arrived.
    fn due(&self) -> Option<Instant> {
        let at = self.slot(self.next?)? + self.delay;
        let wait = (at - self.now()).max(0.0);
        Some(Instant::now() + Duration::from_secs_f64(wait / 1000.0))
    }

    /// Play the next chunk: decoded, or guessed if it never came (and
    /// shortened by a frame or more while the delay comes down).
    fn play(&mut self) -> Result<Vec<f32>> {
        let skip = self.adjust();
        let n = self.next.expect("due only once anchored");
        self.next = Some(n + 1);
        let frames = self.chunks.remove(&n);
        self.played += 1;
        self.concealed += u32::from(frames.is_none());
        // Anything older can't be played any more.
        self.chunks.retain(|k, _| *k > n);
        let mut pcm = vec![0.0f32; CHUNK];
        for (i, out) in pcm.chunks_mut(FRAME).enumerate() {
            let frame = frames
                .as_ref()
                .and_then(|f| f.get(i))
                .map_or(&[][..], |f| f.as_slice());
            if let Err(e) = self.decoder.decode_float(frame, out, false) {
                tracing::debug!("audio frame not decoded: {e}");
                out.fill(0.0);
            }
        }
        // Every frame went through the decoder (it keeps state); the
        // first `skip` aren't played.
        pcm.drain(..skip * FRAME);
        Ok(pcm)
    }

    /// How late (after the first packet's pace) [`ON_TIME`] of recent
    /// chunks were.
    /// How late the fastest recent chunk was. Lateness is measured from
    /// the first packet, which may itself have been slow: then the others
    /// are early, and the delay goes below zero to match.
    fn fastest(&self) -> f64 {
        self.lateness
            .iter()
            .copied()
            .fold(f64::INFINITY, f64::min)
            .min(self.on_time())
    }

    fn on_time(&self) -> f64 {
        let mut sorted: Vec<f64> = self.lateness.iter().copied().collect();
        if sorted.is_empty() {
            return 0.0;
        }
        sorted.sort_by(f64::total_cmp);
        sorted[((sorted.len() - 1) as f64 * ON_TIME).round() as usize]
    }

    /// Once a second, move the delay to what recent chunks need: later at
    /// once (a short gap), earlier by leaving out 20 ms frames of the next
    /// chunk (one at a time, unless it is far off). Returns the frames to
    /// leave out.
    fn adjust(&mut self) -> usize {
        let now = self.now();
        if now - self.adjusted_at < 1000.0 || self.lateness.len() < 20 {
            return 0;
        }
        self.adjusted_at = now;
        let fastest = self.fastest();
        let target = (self.on_time() + MARGIN_MS).clamp(fastest, fastest + MAX_DELAY_MS);
        if target > self.delay {
            self.delay = target;
            return 0;
        }
        let frame_ms = 1000.0 * FRAME as f64 / f64::from(RATE);
        if self.delay - target > CATCH_UP_MS {
            // Far behind (a slow stretch has passed): jump to where the
            // talking is now, dropping what would have played meanwhile.
            self.delay = target;
            while let Some(n) = self.next {
                let behind = self.slot(n).map_or(0.0, |at| now - at - self.delay);
                if behind < CALL_GAP.as_millis() as f64 {
                    break;
                }
                self.chunks.remove(&n);
                self.next = Some(n + 1);
            }
            return 0;
        }
        // A frame of slack is kept, so the delay doesn't chase every
        // wobble down.
        let over = ((self.delay - target) / frame_ms).floor() as usize;
        let skip = match over {
            0 | 1 => 0,
            n if n > FRAMES => FRAMES - 1,
            _ => 1,
        };
        self.delay -= skip as f64 * frame_ms;
        skip
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (Directions, Directions) {
        let (id, key) = ([3u8; 16], [9u8; 32]);
        (
            Directions::new(&id, &key, true, 0),
            Directions::new(&id, &key, false, 0),
        )
    }

    #[test]
    fn packets_are_one_fixed_size_and_only_the_other_side_opens_them() -> Result<()> {
        let (caller, callee) = keys();
        let me = MixAddress("line.a@gateway".into());
        let mut encoder = encoder()?;
        let tone: Vec<f32> = (0..CHUNK).map(|i| (i as f32 * 0.05).sin() * 0.3).collect();
        let chunks: Vec<Chunk> = (0..3)
            .map(|n| Ok((n, encode(&mut encoder, &tone)?)))
            .collect::<Result<_>>()?;
        let packet = seal(&caller, 7, &me, 87, &chunks)?;
        assert_eq!(packet.len(), PACKET);
        assert_eq!(filler().len(), PACKET, "filler looks the same");
        assert!(
            privmsg_transport::pad(&packet)?.len() == privmsg_transport::PAD_BLOCK,
            "one Nym packet"
        );
        let silent = seal(
            &caller,
            8,
            &me,
            0,
            &[(0, encode(&mut encoder, &[0.0; CHUNK])?)],
        )?;
        assert_eq!(silent.len(), packet.len(), "silence costs the same");

        let got = open(&callee, &packet).expect("callee opens it");
        assert_eq!(got.from, me);
        assert_eq!(got.chunks, chunks);
        assert_eq!(got.line, 0);
        assert_eq!(got.heard, Some(87), "how much of theirs we get");
        // A later line of the caller's: same key, but a nonce of its own.
        let (id, key) = ([3u8; 16], [9u8; 32]);
        let second = Directions::new(&id, &key, true, 1);
        let again = seal(&second, 7, &me, u8::MAX, &chunks)?;
        assert_ne!(again[HEADER..], packet[HEADER..], "no nonce reused");
        let again = open(&callee, &again).expect("opens");
        assert_eq!((again.line, again.heard), (1, None));
        assert!(open(&caller, &packet).is_none(), "not our own direction");
        assert!(open(&callee, &filler()).is_none());
        let mut tampered = packet.clone();
        tampered[0] ^= 1;
        assert!(
            open(&callee, &tampered).is_none(),
            "number is authenticated"
        );
        Ok(())
    }

    #[test]
    fn opus_frames_have_a_constant_size() -> Result<()> {
        let mut encoder = encoder()?;
        let tone: Vec<f32> = (0..CHUNK).map(|i| (i as f32 * 0.07).sin() * 0.5).collect();
        let noise: Vec<f32> = (0..CHUNK)
            .map(|i| ((i * 7919 % 1000) as f32 / 1000.0 - 0.5) * 0.8)
            .collect();
        let sizes: Vec<usize> = [tone, noise, vec![0.0; CHUNK]]
            .iter()
            .flat_map(|pcm| encode(&mut encoder, pcm).unwrap())
            .map(|f| f.len())
            .collect();
        assert!(sizes.iter().all(|s| *s == sizes[0]), "{sizes:?}");
        Ok(())
    }

    /// Two people on the in-memory network, in a conversation.
    struct Side {
        _dir: tempfile::TempDir,
        node: Node,
        mux: Mux<privmsg_transport::memory::MemoryNetwork>,
        calls: Calls,
        updates: Vec<CallUpdate>,
    }

    impl Side {
        fn new(net: &privmsg_transport::memory::MemoryNetwork) -> Result<Self> {
            let dir = tempfile::tempdir()?;
            Ok(Self {
                node: Node::create(&dir.path().join("p"), "test passphrase")?,
                mux: Mux::new(net.clone()),
                calls: Calls::new(AudioPipe::default(), None),
                updates: Vec::new(),
                _dir: dir,
            })
        }

        /// Handle one thing that happened: a frame or call-line news.
        async fn step(&mut self) -> Result<()> {
            tokio::select! {
                arrived = self.mux.recv() => {
                    let (slot, msg) = arrived?;
                    for event in self.node.handle_incoming(&mut self.mux, &slot, &msg.payload).await? {
                        if let crate::app::Event::Call { contact, signal } = event {
                            let update = self.calls.on_signal(&mut self.node, &mut self.mux, &contact, signal).await;
                            self.updates.extend(update);
                        }
                    }
                }
                news = self.calls.next() => {
                    let update = self.calls.on_news(&mut self.node, &mut self.mux, news).await;
                    self.updates.extend(update);
                }
            }
            Ok(())
        }

        /// How loud what came out of the speaker in the last `ms` was.
        fn heard(&self, ms: usize) -> f32 {
            let mut out = vec![0.0f32; RATE as usize / 1000 * ms];
            self.calls.audio().pull_speaker(&mut out);
            out.iter().map(|s| s.abs()).fold(0.0, f32::max)
        }
    }

    /// Run both sides (and feed both microphones a tone) until `done`.
    async fn run_until(
        a: &mut Side,
        b: &mut Side,
        limit: Duration,
        mut done: impl FnMut(&Side, &Side) -> bool,
    ) -> Result<()> {
        let tone: Vec<f32> = (0..CHUNK / 10)
            .map(|i| (i as f32 * 0.06).sin() * 0.4)
            .collect();
        let deadline = Instant::now() + limit;
        let mut feed = interval(Duration::from_millis(10));
        while !done(a, b) {
            if Instant::now() > deadline {
                bail!("timed out; a: {:?}, b: {:?}", a.updates, b.updates);
            }
            tokio::select! {
                r = a.step() => r?,
                r = b.step() => r?,
                _ = feed.tick() => {
                    a.calls.audio().push_mic(&tone);
                    b.calls.audio().push_mic(&tone);
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_call_rings_connects_carries_sound_both_ways_and_ends() -> Result<()> {
        let net = privmsg_transport::memory::MemoryNetwork::default();
        let (mut alice, mut bob) = (Side::new(&net)?, Side::new(&net)?);
        let code = bob.node.create_invite(&mut bob.mux, "alice").await?;
        alice
            .node
            .accept_invite(&mut alice.mux, &code, "bob")
            .await?;
        let (slot, msg) = bob.mux.recv().await?;
        bob.node
            .handle_incoming(&mut bob.mux, &slot, &msg.payload)
            .await?;

        alice
            .calls
            .start(&mut alice.node, &mut alice.mux, "bob")
            .await?;
        assert!(alice
            .calls
            .start(&mut alice.node, &mut alice.mux, "bob")
            .await
            .is_err());
        run_until(&mut alice, &mut bob, Duration::from_secs(5), |_, b| {
            !b.updates.is_empty()
        })
        .await?;
        assert_eq!(
            bob.updates.remove(0),
            CallUpdate::Ringing {
                contact: "alice".into()
            }
        );
        assert_eq!(bob.calls.info().unwrap().state, CallState::Ringing);

        bob.calls.accept(&bob.mux)?;
        run_until(&mut alice, &mut bob, Duration::from_secs(5), |a, b| {
            a.calls
                .info()
                .is_some_and(|i| i.state == CallState::Talking)
                && b.calls
                    .info()
                    .is_some_and(|i| i.state == CallState::Talking)
        })
        .await?;
        // A second of talking, then both speakers should have played the tone.
        let talk = Instant::now() + Duration::from_millis(1500);
        run_until(&mut alice, &mut bob, Duration::from_secs(5), |_, _| {
            Instant::now() > talk
        })
        .await?;
        assert!(alice.heard(400) > 0.1, "alice hears bob");
        assert!(bob.heard(400) > 0.1, "bob hears alice");

        let ended = alice.calls.hang_up(&mut alice.node, &mut alice.mux).await;
        assert!(
            matches!(ended, Some(CallUpdate::Ended { ref note, .. }) if note.starts_with("Call · 0:0"))
        );
        bob.updates.clear();
        run_until(&mut alice, &mut bob, Duration::from_secs(5), |_, b| {
            !b.updates.is_empty()
        })
        .await?;
        assert!(
            matches!(&bob.updates[0], CallUpdate::Ended { note, .. } if note.starts_with("Call · 0:0"))
        );
        assert!(!alice.calls.is_busy() && !bob.calls.is_busy());
        let note = &bob.node.contact("alice")?.history.last().unwrap().text;
        assert!(note.starts_with("Call · "), "noted in the chat: {note}");
        Ok(())
    }

    #[tokio::test]
    async fn a_call_survives_its_line_dying() -> Result<()> {
        let net = privmsg_transport::memory::MemoryNetwork::default();
        let (mut alice, mut bob) = (Side::new(&net)?, Side::new(&net)?);
        let code = bob.node.create_invite(&mut bob.mux, "alice").await?;
        alice
            .node
            .accept_invite(&mut alice.mux, &code, "bob")
            .await?;
        let (slot, msg) = bob.mux.recv().await?;
        bob.node
            .handle_incoming(&mut bob.mux, &slot, &msg.payload)
            .await?;
        alice
            .calls
            .start(&mut alice.node, &mut alice.mux, "bob")
            .await?;
        run_until(&mut alice, &mut bob, Duration::from_secs(5), |_, b| {
            !b.updates.is_empty()
        })
        .await?;
        bob.calls.accept(&bob.mux)?;
        let talk = Instant::now() + Duration::from_millis(1500);
        run_until(&mut alice, &mut bob, Duration::from_secs(5), |_, _| {
            Instant::now() > talk
        })
        .await?;

        // Alice's line (the first one made) dies, as when a phone changes
        // networks.
        net.kill("call-0");
        alice.updates.clear();
        run_until(&mut alice, &mut bob, Duration::from_secs(5), |a, _| {
            !a.updates.is_empty()
        })
        .await?;
        assert_eq!(
            alice.updates[0],
            CallUpdate::Reconnecting {
                contact: "bob".into()
            }
        );
        let talk = Instant::now() + Duration::from_millis(2500);
        alice.heard(1000);
        bob.heard(1000);
        run_until(&mut alice, &mut bob, Duration::from_secs(6), |_, _| {
            Instant::now() > talk
        })
        .await?;
        assert!(alice.heard(400) > 0.1, "alice hears bob again");
        assert!(bob.heard(400) > 0.1, "bob hears alice on her new line");
        assert!(
            alice.calls.is_busy() && bob.calls.is_busy(),
            "still in the call"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_poor_line_is_replaced() -> Result<()> {
        let net = privmsg_transport::memory::MemoryNetwork::default();
        let (mut alice, mut bob) = (Side::new(&net)?, Side::new(&net)?);
        let code = bob.node.create_invite(&mut bob.mux, "alice").await?;
        alice
            .node
            .accept_invite(&mut alice.mux, &code, "bob")
            .await?;
        let (slot, msg) = bob.mux.recv().await?;
        bob.node
            .handle_incoming(&mut bob.mux, &slot, &msg.payload)
            .await?;
        alice
            .calls
            .start(&mut alice.node, &mut alice.mux, "bob")
            .await?;
        run_until(&mut alice, &mut bob, Duration::from_secs(5), |_, b| {
            !b.updates.is_empty()
        })
        .await?;
        bob.calls.accept(&bob.mux)?;
        run_until(&mut alice, &mut bob, Duration::from_secs(5), |a, b| {
            a.calls
                .info()
                .is_some_and(|i| i.state == CallState::Talking)
                && b.calls
                    .info()
                    .is_some_and(|i| i.state == CallState::Talking)
        })
        .await?;

        // Alice's line (the first made) gets only a quarter of its packets
        // through, but stays up: a bad gateway. Bob hears that and says so
        // in his packets; Alice replaces her line.
        net.degrade("call-0", 4);
        alice.updates.clear();
        run_until(&mut alice, &mut bob, Duration::from_secs(40), |a, _| {
            !a.updates.is_empty()
        })
        .await?;
        assert_eq!(
            alice.updates[0],
            CallUpdate::Reconnecting {
                contact: "bob".into()
            }
        );
        let talk = Instant::now() + Duration::from_secs(3);
        run_until(&mut alice, &mut bob, Duration::from_secs(6), |_, _| {
            Instant::now() > talk
        })
        .await?;
        bob.heard(1000);
        let talk = Instant::now() + Duration::from_millis(1500);
        run_until(&mut alice, &mut bob, Duration::from_secs(5), |_, _| {
            Instant::now() > talk
        })
        .await?;
        assert!(bob.heard(400) > 0.1, "bob hears alice on her new line");
        Ok(())
    }

    #[tokio::test]
    async fn an_unanswered_call_is_declined_or_missed() -> Result<()> {
        let net = privmsg_transport::memory::MemoryNetwork::default();
        let (mut alice, mut bob) = (Side::new(&net)?, Side::new(&net)?);
        let code = bob.node.create_invite(&mut bob.mux, "alice").await?;
        alice
            .node
            .accept_invite(&mut alice.mux, &code, "bob")
            .await?;
        let (slot, msg) = bob.mux.recv().await?;
        bob.node
            .handle_incoming(&mut bob.mux, &slot, &msg.payload)
            .await?;

        alice
            .calls
            .start(&mut alice.node, &mut alice.mux, "bob")
            .await?;
        run_until(&mut alice, &mut bob, Duration::from_secs(5), |_, b| {
            !b.updates.is_empty()
        })
        .await?;
        let declined = bob.calls.hang_up(&mut bob.node, &mut bob.mux).await;
        assert!(
            matches!(declined, Some(CallUpdate::Ended { ref note, .. }) if note == "Declined call")
        );
        run_until(&mut alice, &mut bob, Duration::from_secs(5), |a, _| {
            !a.updates.is_empty()
        })
        .await?;
        assert!(matches!(&alice.updates[0], CallUpdate::Ended { note, .. } if note == "Declined"));

        // An offer that took too long to arrive doesn't ring.
        let late = CallSignal::Offer {
            call: [1; 16],
            key: [2; 32],
            at: unix_now() - 600,
        };
        let update = bob
            .calls
            .on_signal(&mut bob.node, &mut bob.mux, "alice", late)
            .await;
        assert_eq!(
            update,
            Some(CallUpdate::Missed {
                contact: "alice".into()
            })
        );
        assert!(!bob.calls.is_busy());
        let alice_entry = bob.node.contact("alice")?;
        assert_eq!(alice_entry.history.last().unwrap().text, "Missed call");
        assert!(alice_entry.unread >= 1);
        Ok(())
    }

    /// Run the pipe for `secs` of simulated time, 1 ms a step: the
    /// microphone hands over `mic_block` samples at a time (each block
    /// `mic_late` ms after it is due, every other block), the speaker asks
    /// for `speaker_block` at a time, and the call takes and gives a chunk
    /// every 100 ms, `call_late` ms late every third time. Returns what the
    /// call sent and what the speaker played.
    fn simulate(
        mic_block: usize,
        mic_late: usize,
        speaker_block: usize,
        call_late: usize,
        secs: usize,
    ) -> (Vec<f32>, Vec<f32>) {
        let pipe = AudioPipe::default();
        // A ramp, so that any gap, repeat or skip shows (steps of 2^-20:
        // exact in an f32).
        let source: Vec<f32> = (0..RATE as usize * (secs + 1))
            .map(|i| (i as f32 + 1.0) * STEP)
            .collect();
        let (mut fed, mut sent, mut played) = (0usize, Vec::new(), Vec::new());
        let ms = RATE as usize / 1000;
        let (mut mic_blocks, mut chunks, mut next_mic) = (0, 0, mic_block);
        let mut next_take = CHUNK;
        let mut speaker_at = 0usize;
        for t in (0..RATE as usize * secs).step_by(ms) {
            if t >= next_mic {
                pipe.push_mic(&source[fed..fed + mic_block]);
                fed += mic_block;
                mic_blocks += 1;
                next_mic = mic_block * (mic_blocks + 1) + (mic_blocks % 2) * mic_late * ms;
            }
            if t >= next_take {
                let chunk = pipe.take_mic();
                // What went out comes straight back to be played.
                pipe.play(&chunk);
                sent.extend(chunk);
                chunks += 1;
                next_take = CHUNK * (chunks + 1) + usize::from(chunks % 3 == 0) * call_late * ms;
            }
            while speaker_at + speaker_block <= t {
                let mut out = vec![0.0; speaker_block];
                pipe.pull_speaker(&mut out);
                played.extend(out);
                speaker_at += speaker_block;
            }
        }
        (sent, played)
    }

    const STEP: f32 = 1.0 / 1_048_576.0;

    /// Breaks in a ramp after its first sample: silence within it, or a jump.
    fn breaks(samples: &[f32]) -> usize {
        let start = samples
            .iter()
            .position(|s| *s != 0.0)
            .unwrap_or(samples.len());
        samples[start..]
            .windows(2)
            .filter(|w| w[1] - w[0] != STEP)
            .count()
    }

    #[test]
    fn the_pipe_keeps_speech_whole_whatever_blocks_the_sound_card_uses() {
        for (mic, mic_late, speaker, call_late) in [
            (480, 3, 512, 2),      // a computer: 10 ms blocks
            (4_800, 8, 1_024, 3),  // an iPhone microphone tap: 100 ms lumps
            (4_410, 12, 4_096, 4), // a locked iPhone: big blocks
        ] {
            let (sent, played) = simulate(mic, mic_late, speaker, call_late, 30);
            assert!(
                breaks(&sent) <= 1,
                "mic {mic}: {} breaks in what was sent",
                breaks(&sent)
            );
            assert!(
                breaks(&played) <= 2,
                "speaker {speaker}: {} breaks in what was played",
                breaks(&played)
            );
            // And none of it waits long.
            let lag = |out: &[f32]| out.iter().position(|s| *s != 0.0).unwrap_or(usize::MAX);
            assert!(
                lag(&sent) < CHUNK + mic + 2 * JITTER,
                "mic {mic}: starts late"
            );
            let heard = played.iter().filter(|s| **s != 0.0).count();
            assert!(
                heard > sent.len() - 3 * CHUNK - 2 * MAX_BLOCK,
                "speaker {speaker}: most of it played"
            );
        }
    }

    /// Feed a playout packets every 100 ms (each `late` ms after its
    /// slot, plus the two copies) and play whatever is due, for `secs`.
    async fn stream(
        playout: &mut Playout,
        frames: &[Vec<u8>],
        from: u32,
        secs: u32,
        late: impl Fn(u32) -> u64,
    ) -> Result<()> {
        let base = Instant::now();
        let mut arrivals: Vec<(u64, u32)> = (from..from + secs * 10)
            .map(|n| (u64::from(n - from) * 100 + late(n), n))
            .collect();
        arrivals.sort();
        let mut i = 0;
        for ms in 0..u64::from(secs) * 1000 {
            while i < arrivals.len() && arrivals[i].0 <= ms {
                let n = arrivals[i].1;
                let copies = (n.saturating_sub(2)..=n)
                    .rev()
                    .map(|k| (k, frames.to_vec()));
                playout.arrive(copies.collect());
                i += 1;
            }
            while playout.due().is_some_and(|d| d <= Instant::now()) {
                playout.play()?;
            }
            tokio::time::advance(Duration::from_millis(1)).await;
            let _ = base;
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_stall_does_not_leave_the_call_lagging() -> Result<()> {
        let mut encoder = encoder()?;
        let frames = encode(&mut encoder, &[0.1; CHUNK])?;
        let mut playout = Playout::new(decoder()?);
        // 20 s of a steady path (up to 80 ms of wobble), with a 4 s stall
        // in the middle whose packets all come out when it ends.
        stream(&mut playout, &frames, 0, 20, |n| {
            let wobble = u64::from(n * 37 % 80);
            if (80..120).contains(&n) {
                (120 - u64::from(n)) * 100 + wobble
            } else {
                wobble
            }
        })
        .await?;
        assert!(
            playout.delay < 250.0,
            "playing {:.0} ms behind after the stall",
            playout.delay
        );

        // A path that really got slower (by 1.5 s, for good) is followed.
        stream(&mut playout, &frames, 200, 10, |n| {
            1_500 + u64::from(n * 37 % 80)
        })
        .await?;
        assert!(
            playout.delay > 1_400.0,
            "follows a slower path: {:.0}",
            playout.delay
        );
        // And when it is fast again, the delay comes back down soon.
        stream(&mut playout, &frames, 300, 40, |n| u64::from(n * 37 % 80)).await?;
        assert!(playout.delay < 250.0, "back down: {:.0}", playout.delay);

        // Now and then a packet many seconds late (seen on mainnet): no
        // effect on the delay.
        let concealed = playout.concealed;
        stream(&mut playout, &frames, 700, 40, |n| {
            if n % 37 == 0 {
                20_000
            } else {
                u64::from(n * 37 % 80)
            }
        })
        .await?;
        assert!(
            playout.delay < 250.0,
            "stragglers ignored: {:.0}",
            playout.delay
        );
        assert!(
            playout.concealed - concealed < 10,
            "copies cover the stragglers"
        );

        // A path slower by 6 s for good: playout starts again on it, and
        // plays nearly everything.
        let concealed = playout.concealed;
        stream(&mut playout, &frames, 1_100, 20, |n| {
            6_000 + u64::from(n * 37 % 80)
        })
        .await?;
        assert!(
            playout.delay < 400.0,
            "on the new timing: {:.0}",
            playout.delay
        );
        assert!(
            playout.concealed - concealed < 120,
            "{} concealed",
            playout.concealed - concealed
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_first_packet_does_not_delay_the_whole_call() -> Result<()> {
        let mut encoder = encoder()?;
        let frames = encode(&mut encoder, &[0.1; CHUNK])?;
        let mut playout = Playout::new(decoder()?);
        // The first packets are 2 s late (a queue at the start, draining
        // over 4 s, in order); after that they come within 80 ms.
        stream(&mut playout, &frames, 0, 15, |n| {
            2_000u64.saturating_sub(u64::from(n) * 50) + u64::from(n * 37 % 80)
        })
        .await?;
        // Timed from that first packet, the others are ~2 s early: the
        // delay goes below zero to play them as soon as they are due.
        assert!(playout.delay < -1_700.0, "delay {:.0}", playout.delay);
        assert!(playout.delay - playout.fastest() < 250.0);
        Ok(())
    }

    #[test]
    fn playout_fills_gaps_from_copies_and_conceals_the_rest() -> Result<()> {
        let mut encoder = encoder()?;
        let tone: Vec<f32> = (0..CHUNK).map(|i| (i as f32 * 0.05).sin() * 0.3).collect();
        let frames = encode(&mut encoder, &tone)?;
        let mut playout = Playout::new(decoder()?);
        // Packet 0, then packet 2 carrying copies of 1 and 0.
        playout.arrive(vec![(0, frames.clone())]);
        playout.arrive(vec![(2, frames.clone()), (1, frames.clone()), (0, frames)]);
        for _ in 0..3 {
            let pcm = playout.play()?;
            assert!(pcm.iter().any(|s| s.abs() > 0.01), "chunk has sound");
        }
        // Chunk 3 never came: concealed, still the right length.
        assert_eq!(playout.play()?.len(), CHUNK);
        assert!(playout.chunks.is_empty());
        Ok(())
    }
}
