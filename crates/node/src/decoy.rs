//! Decoy traffic: when enabled, every conversation sends on its own Poisson
//! clock while privmsg is connected. On each tick the oldest frame the node
//! holds for that contact goes out (`Node::tick`), or a decoy if nothing
//! is waiting, so the stream of frames arriving at a contact's gateway is
//! the same whether you are typing or idle. Everything waits for the next
//! tick (mean = the interval): messages, and also deletes, timer changes
//! and address changes, which would otherwise stand out.
//!
//! This hides *when* and *how much* two people talk from anyone counting
//! packets at the recipient's gateway or correlating both ends over time —
//! the residual signal Nym's own cover traffic leaves. It is Loopix-style
//! constant-rate sending, not a differential-privacy mechanism: being online
//! at all is still visible, and no formal bound is claimed.

use std::collections::HashMap;
use std::time::Duration;

use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::OsRng;
use tokio::time::Instant;

/// Shortest interval accepted, so a typo can't flood the mixnet.
pub const MIN_INTERVAL: u32 = 2;

/// The clocks. What goes out on a tick is the node's business.
pub struct Scheduler {
    mean: Duration,
    next: HashMap<String, Instant>,
}

impl Scheduler {
    pub fn new(mean: Duration, contacts: impl IntoIterator<Item = String>) -> Self {
        let mut scheduler = Self {
            mean,
            next: HashMap::new(),
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

    /// The conversation whose tick comes first, and when.
    pub fn next_due(&self) -> Option<(String, Instant)> {
        self.next
            .iter()
            .min_by_key(|(_, at)| **at)
            .map(|(name, at)| (name.clone(), *at))
    }

    /// `name`'s tick has come: schedule the next one.
    pub fn tick(&mut self, name: &str) {
        let at = Instant::now() + self.interval();
        if let Some(next) = self.next.get_mut(name) {
            *next = at;
        }
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
    fn earliest_conversation_is_due_first_and_ticks_move_on() {
        let mut s = Scheduler::new(Duration::from_secs(10), ["a".to_string(), "b".to_string()]);
        let (first, at) = s.next_due().unwrap();
        assert!(s.next.values().all(|t| *t >= at));
        s.tick(&first);
        assert_ne!(s.next[&first], at, "rescheduled");
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
