//! Decoy traffic: when enabled, every conversation sends on its own Poisson
//! clock while privmsg is connected. On each tick the oldest queued message
//! goes out, or a decoy if nothing is waiting, so the stream of frames
//! arriving at a contact's gateway is the same whether you are typing or
//! idle. Real messages wait for the next tick (mean = the interval).
//!
//! This hides *when* and *how much* two people talk from anyone counting
//! packets at the recipient's gateway or correlating both ends over time —
//! the residual signal Nym's own cover traffic leaves. It is Loopix-style
//! constant-rate sending, not a differential-privacy mechanism: being online
//! at all is still visible, and no formal bound is claimed.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::OsRng;
use tokio::time::Instant;

/// Shortest interval accepted, so a typo can't flood the mixnet.
pub const MIN_INTERVAL: u32 = 2;

pub struct Scheduler {
    mean: Duration,
    next: HashMap<String, Instant>,
    outbox: HashMap<String, VecDeque<String>>,
}

impl Scheduler {
    pub fn new(mean: Duration, contacts: impl IntoIterator<Item = String>) -> Self {
        let mut scheduler = Self {
            mean,
            next: HashMap::new(),
            outbox: HashMap::new(),
        };
        for name in contacts {
            scheduler.add(name);
        }
        scheduler
    }

    /// Start a clock for a new conversation.
    pub fn add(&mut self, name: String) {
        let at = Instant::now() + self.interval();
        self.next.entry(name).or_insert(at);
    }

    pub fn queue(&mut self, name: &str, text: String) {
        self.outbox
            .entry(name.to_string())
            .or_default()
            .push_back(text);
    }

    pub fn queued(&self) -> usize {
        self.outbox.values().map(VecDeque::len).sum()
    }

    /// The conversation whose tick comes first, and when.
    pub fn next_due(&self) -> Option<(String, Instant)> {
        self.next
            .iter()
            .min_by_key(|(_, at)| **at)
            .map(|(name, at)| (name.clone(), *at))
    }

    /// `name`'s tick has come: schedule the next one and return the message
    /// to send now, if one is waiting (otherwise send a decoy).
    pub fn tick(&mut self, name: &str) -> Option<String> {
        let at = Instant::now() + self.interval();
        if let Some(next) = self.next.get_mut(name) {
            *next = at;
        }
        self.outbox.get_mut(name).and_then(VecDeque::pop_front)
    }

    /// Everything still queued, for sending before exit.
    pub fn drain(&mut self) -> Vec<(String, String)> {
        let mut all = Vec::new();
        for (name, queue) in self.outbox.iter_mut() {
            all.extend(queue.drain(..).map(|text| (name.clone(), text)));
        }
        all
    }

    /// Exponentially distributed, so ticks form a Poisson process.
    fn interval(&self) -> Duration {
        // Uniform in (0, 1]: 53 random bits, never zero.
        let u = ((OsRng.next_u64() >> 11) + 1) as f64 / (1u64 << 53) as f64;
        self.mean.mul_f64(-u.ln())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_messages_take_the_place_of_decoys_in_order() {
        let mut s = Scheduler::new(Duration::from_secs(10), ["bob".to_string()]);
        assert_eq!(s.tick("bob"), None, "nothing queued: decoy");
        s.queue("bob", "one".into());
        s.queue("bob", "two".into());
        assert_eq!(s.queued(), 2);
        assert_eq!(s.tick("bob").as_deref(), Some("one"));
        assert_eq!(s.tick("bob").as_deref(), Some("two"));
        assert_eq!(s.tick("bob"), None);
    }

    #[test]
    fn earliest_conversation_is_due_first_and_drain_empties() {
        let mut s = Scheduler::new(Duration::from_secs(10), ["a".to_string(), "b".to_string()]);
        let (first, at) = s.next_due().unwrap();
        assert!(s.next.values().all(|t| *t >= at));
        s.tick(&first);
        s.queue("a", "x".into());
        assert_eq!(s.drain(), vec![("a".to_string(), "x".to_string())]);
        assert_eq!(s.queued(), 0);
    }

    #[test]
    fn intervals_average_to_the_mean() {
        let s = Scheduler::new(Duration::from_secs(10), []);
        let n = 20_000;
        let total: f64 = (0..n).map(|_| s.interval().as_secs_f64()).sum();
        let mean = total / n as f64;
        assert!((9.5..10.5).contains(&mean), "mean {mean}");
    }
}
