//! The real transport: Nym mixnet clients, one per slot.

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use nym_sdk::mixnet::{
    IncludedSurbs, MixnetClient, MixnetClientBuilder, MixnetMessageSender, Recipient, StoragePaths,
};
use tokio::time::{sleep, Instant};

use crate::{pad, unpad, IncomingMessage, MixAddress, Network, Transport};

/// The Nym mainnet. Each slot keeps its client keys and gateway registration
/// in its own directory under `root`, so its address survives restarts.
pub struct NymNetwork {
    root: PathBuf,
}

impl NymNetwork {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
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
        NymTransport::connect(&self.dir(slot)?).await
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
}

impl NymTransport {
    /// Connect to the Nym mainnet, keeping the client's keys and gateway
    /// registration in `storage_dir` so the overlay address survives restarts.
    ///
    /// Background cover traffic and the Poisson send stream are on by default
    /// in the SDK. Do NOT disable them — they are the anonymity, not overhead
    /// to trim.
    pub async fn connect(storage_dir: &Path) -> Result<Self> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(storage_dir)
            .with_context(|| format!("create {}", storage_dir.display()))?;
        let paths = StoragePaths::new_from_dir(storage_dir)?;
        let client = MixnetClientBuilder::new_with_default_storage(paths)
            .await?
            .build()?
            .connect_to_mixnet()
            .await
            .context("connect to the Nym mixnet")?;
        Ok(Self { client })
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
        // Poisson sender; give the last ones a moment to leave.
        sleep(Duration::from_secs(3)).await;
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
            .context("hand message to the mixnet client")
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
        let net = NymNetwork::new(PathBuf::from("/tmp/root"));
        assert!(net.dir("../etc").is_err());
        assert!(net.dir("").is_err());
        assert_eq!(net.dir("ab12").unwrap(), PathBuf::from("/tmp/root/ab12"));
    }
}
