//! The real transport: Nym mixnet clients, one per slot.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use nym_sdk::mixnet::{
    IncludedSurbs, MixnetClient, MixnetClientBuilder, MixnetMessageSender, Recipient, StoragePaths,
};
use nym_sdk::DebugConfig;
use tokio::time::{sleep, Instant};

use crate::{pad, unpad, DataMode, IncomingMessage, MixAddress, Network, Tor, Transport};

/// The Nym mainnet. Each slot keeps its client keys and gateway registration
/// in its own directory under `root`, so its address survives restarts.
pub struct NymNetwork {
    root: PathBuf,
    mode: DataMode,
    tor: Option<Tor>,
}

impl NymNetwork {
    pub fn new(root: PathBuf, mode: DataMode) -> Self {
        Self {
            root,
            mode,
            tor: None,
        }
    }

    /// Reach the gateways through `tor` from now on. Kept running for as
    /// long as this network lives.
    pub fn with_tor(mut self, tor: Tor) -> Result<Self> {
        tor.route_nym()?;
        self.tor = Some(tor);
        Ok(self)
    }

    fn dir(&self, slot: &str) -> Result<PathBuf> {
        if slot.is_empty() || !slot.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(anyhow!("invalid slot name {slot:?}"));
        }
        Ok(self.root.join(slot))
    }
}

impl Network for NymNetwork {
    type Endpoint = NymTransport;

    /// A new slot registers with a gateway chosen uniformly at random by the
    /// SDK, so two slots of the same user don't share a gateway by design.
    async fn open(&self, slot: &str) -> Result<NymTransport> {
        NymTransport::connect(&self.dir(slot)?, self.mode, self.tor.is_some()).await
    }

    fn forget(&self, slot: &str) -> Result<()> {
        let dir = self.dir(slot)?;
        match std::fs::remove_dir_all(&dir) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(e).with_context(|| format!("remove {}", dir.display()))
            }
            _ => Ok(()),
        }
    }
}

/// Thin wrapper over a Nym `MixnetClient`: one mix address.
pub struct NymTransport {
    client: MixnetClient,
    mode: DataMode,
    last_send: Option<Instant>,
}

impl NymTransport {
    /// Connect to the Nym mainnet, keeping the client's keys and gateway
    /// registration in `storage_dir` so the overlay address survives restarts.
    ///
    /// `mode` sets the rates of the Poisson send stream and of loop cover.
    /// Never disable either stream — they are the anonymity, not overhead to
    /// trim; [`DataMode`] only slows them down.
    ///
    /// With `over_tor`, a new address only picks gateways that speak TLS, so
    /// the Tor exit sees an encrypted stream rather than Nym's websocket.
    pub async fn connect(storage_dir: &Path, mode: DataMode, over_tor: bool) -> Result<Self> {
        crate::create_private_dir(storage_dir)
            .with_context(|| format!("create {}", storage_dir.display()))?;
        let paths = StoragePaths::new_from_dir(storage_dir)?;
        let mut debug = DebugConfig::default();
        if let Some((send, cover)) = mode.rates() {
            debug.traffic.message_sending_average_delay = send;
            debug.cover_traffic.loop_cover_traffic_average_delay = cover;
        }
        // No collector is configured anyway; make sure nothing is reported.
        debug.stats_reporting.enabled = false;
        let client = MixnetClientBuilder::new_with_default_storage(paths)
            .await?
            .debug_config(debug)
            .force_tls(over_tor)
            .build()?
            .connect_to_mixnet()
            .await
            .context("connect to the Nym mixnet")?;
        Ok(Self {
            client,
            mode,
            last_send: None,
        })
    }

    /// Wait until everything queued has been handed to the mixnet (or
    /// `timeout` passes). `send` only enqueues; exiting right after it would
    /// drop the message.
    pub async fn flush(&self, timeout: Duration) {
        let lanes = self.client.shared_lane_queue_lengths();
        let deadline = Instant::now() + timeout;
        // A just-sent message may still be on its way into the lane queue.
        sleep(Duration::from_millis(500)).await;
        while lanes.total() > 0 && Instant::now() < deadline {
            sleep(Duration::from_millis(200)).await;
        }
        // The queue counts messages, not packets already scheduled by the
        // Poisson sender; give the last ones time to get their slots. Only
        // needed if something was sent lately.
        let grace = Duration::from_secs(3) + self.mode.send_gap() * 5;
        if let Some(sent) = self.last_send {
            sleep(grace.saturating_sub(sent.elapsed())).await;
        }
    }

    /// Flush pending sends, then close the connection to the gateway.
    pub async fn disconnect(self) {
        self.flush(Duration::from_secs(30)).await;
        self.client.disconnect().await;
    }
}

impl Transport for NymTransport {
    fn address(&self) -> MixAddress {
        MixAddress(self.client.nym_address().to_string())
    }

    /// The payload is MLS ciphertext; the mixnet adds a second, routing layer
    /// of Sphinx encryption on top. No reply SURBs are attached: contacts
    /// already know each other's address, so SURBs would only cost bandwidth.
    async fn send(&mut self, to: &MixAddress, payload: &[u8]) -> Result<()> {
        let recipient: Recipient =
            to.0.parse()
                .map_err(|e| anyhow!("invalid mix address {:?}: {e}", to.0))?;
        self.client
            .send_message(recipient, pad(payload)?, IncludedSurbs::none())
            .await
            .context("hand message to the mixnet client")?;
        self.last_send = Some(Instant::now());
        Ok(())
    }

    /// Cover/decoy packets are handled by the SDK and never surface here.
    /// Malformed frames are dropped rather than ending the stream.
    async fn recv(&mut self) -> Result<IncomingMessage> {
        loop {
            let msg = self
                .client
                .next()
                .await
                .ok_or_else(|| anyhow!("mixnet client shut down"))?;
            if msg.message.is_empty() {
                continue;
            }
            match unpad(&msg.message) {
                Ok(payload) => return Ok(IncomingMessage { payload }),
                Err(e) => tracing::warn!("dropping malformed frame: {e}"),
            }
        }
    }

    async fn close(self) {
        self.disconnect().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_nym_address_is_rejected() {
        assert!("not-an-address".parse::<Recipient>().is_err());
    }

    #[test]
    fn nym_slot_names_cannot_escape_the_root() {
        let net = NymNetwork::new(PathBuf::from("/tmp/root"), DataMode::Saver);
        assert!(net.dir("../etc").is_err());
        assert!(net.dir("").is_err());
        assert_eq!(net.dir("ab12").unwrap(), PathBuf::from("/tmp/root/ab12"));
    }
}
