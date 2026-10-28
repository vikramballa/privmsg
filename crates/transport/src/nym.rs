//! The real transport: Nym mixnet clients, one per slot plus the sender.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use nym_sdk::mixnet::{
    IncludedSurbs, MixnetClient, MixnetClientBuilder, MixnetMessageSender, NymTopology, Recipient,
    StoragePaths,
};
use nym_sdk::{
    DebugConfig, NymApiTopologyProvider, NymApiTopologyProviderConfig, NymNetworkDetails,
    TopologyProvider,
};
use tokio::sync::Mutex;
use tokio::time::{sleep, Instant};

use crate::{pad, unpad, DataMode, IncomingMessage, MixAddress, Network, Tor, Transport};

/// Gateways a new address tries before giving up.
const NEW_ADDRESS_TRIES: u32 = 3;

/// Directory of the sender's keys. Slot names are random hex, so they
/// can't collide with it.
const SENDER_DIR: &str = "sender";

/// The Nym mainnet. Each slot keeps its client keys and gateway registration
/// in its own directory under `root`, so its address survives restarts.
pub struct NymNetwork {
    root: PathBuf,
    mode: DataMode,
    tor: Option<Tor>,
    topology: SharedTopology,
}

impl NymNetwork {
    pub fn new(root: PathBuf, mode: DataMode) -> Self {
        Self {
            root,
            mode,
            tor: None,
            topology: SharedTopology::default(),
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
        self.connect(&self.dir(slot)?, Role::Slot).await
    }

    async fn open_sender(&self) -> Result<NymTransport> {
        self.connect(&self.root.join(SENDER_DIR), Role::Sender)
            .await
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

impl NymNetwork {
    /// Connect to the Nym mainnet, keeping the client's keys and gateway
    /// registration in `storage_dir` so the overlay address survives restarts.
    ///
    /// The sender runs both cover streams at the rates of [`DataMode`].
    /// Never disable the sender's streams — they are the anonymity, not
    /// overhead to trim. A slot never sends, so its Poisson send stream would
    /// be pure cover; it runs only slow loop cover instead.
    ///
    /// Over Tor, a new address only picks gateways that speak TLS, so the
    /// Tor exit sees an encrypted stream rather than Nym's websocket.
    ///
    /// A new address registers with a gateway picked at random, and some
    /// picks turn out unusable (down, or no TLS listener despite what the
    /// directory says). Then it starts over with fresh keys and another
    /// pick. An existing address keeps its gateway, since contacts write to
    /// it, and tries once more after a pause (the Nym API it asks first
    /// sometimes answers 502 through a Tor exit).
    async fn connect(&self, storage_dir: &Path, role: Role) -> Result<NymTransport> {
        let fresh = !storage_dir.exists();
        let tries = if fresh { NEW_ADDRESS_TRIES } else { 2 };
        let mut attempt = 1;
        loop {
            match self.connect_once(storage_dir, role).await {
                Err(e) if attempt < tries => {
                    if fresh {
                        tracing::warn!("new address failed ({e:#}); trying another gateway");
                        std::fs::remove_dir_all(storage_dir).ok();
                    } else {
                        tracing::warn!("connecting failed ({e:#}); trying again");
                        sleep(Duration::from_secs(3)).await;
                    }
                    attempt += 1;
                }
                done => return done,
            }
        }
    }

    async fn connect_once(&self, storage_dir: &Path, role: Role) -> Result<NymTransport> {
        crate::create_private_dir(storage_dir)
            .with_context(|| format!("create {}", storage_dir.display()))?;
        let paths = StoragePaths::new_from_dir(storage_dir)?;
        let mut debug = DebugConfig::default();
        match role {
            Role::Sender => {
                if let Some((send, cover)) = self.mode.rates() {
                    debug.traffic.message_sending_average_delay = send;
                    debug.cover_traffic.loop_cover_traffic_average_delay = cover;
                }
            }
            Role::Slot => {
                debug.traffic.disable_main_poisson_packet_distribution = true;
                debug.cover_traffic.loop_cover_traffic_average_delay = self.mode.slot_loop();
            }
        }
        // No collector is configured anyway; make sure nothing is reported.
        debug.stats_reporting.enabled = false;
        let client = MixnetClientBuilder::new_with_default_storage(paths)
            .await?
            .debug_config(debug)
            .force_tls(self.tor.is_some())
            .custom_topology_provider(Box::new(self.topology.clone()))
            .build()?
            .connect_to_mixnet()
            .await
            .context("connect to the Nym mixnet")?;
        Ok(NymTransport {
            client,
            mode: self.mode,
            last_send: None,
        })
    }
}

#[derive(Clone, Copy)]
enum Role {
    Sender,
    Slot,
}

/// One view of the network for every client of this process. Each client
/// asks for a fresh topology every few minutes (about 75 KB from the Nym
/// API); within [`SharedTopology::FRESH`] they all get the same copy.
#[derive(Clone, Default)]
struct SharedTopology(Arc<Mutex<TopologyCache>>);

#[derive(Default)]
struct TopologyCache {
    /// Built on first use, after Tor has been set up as Nym's proxy.
    api: Option<NymApiTopologyProvider>,
    latest: Option<(Instant, NymTopology)>,
}

impl SharedTopology {
    /// Clients refresh every 5 minutes; a bit less than that keeps one
    /// download per round.
    const FRESH: Duration = Duration::from_secs(4 * 60);
}

#[async_trait::async_trait]
impl TopologyProvider for SharedTopology {
    async fn get_new_topology(&mut self) -> Option<NymTopology> {
        let mut cache = self.0.lock().await;
        if let Some((at, topology)) = &cache.latest {
            if at.elapsed() < Self::FRESH {
                return Some(topology.clone());
            }
        }
        if cache.api.is_none() {
            cache.api = Some(
                topology_api()
                    .inspect_err(|e| tracing::warn!("{e:#}"))
                    .ok()?,
            );
        }
        let topology = cache.api.as_mut()?.get_new_topology().await?;
        cache.latest = Some((Instant::now(), topology.clone()));
        Some(topology)
    }
}

/// The SDK's own Nym API topology source, with its default settings.
fn topology_api() -> Result<NymApiTopologyProvider> {
    let urls = NymNetworkDetails::new_mainnet().nym_api_urls();
    let client = nym_http_api_client::ClientBuilder::new_with_fronted_urls(urls)?
        .with_retries(3)
        .build()
        .context("build the Nym API client")?;
    let config = NymApiTopologyProviderConfig::from(DebugConfig::default().topology);
    Ok(NymApiTopologyProvider::new(config, client))
}

/// Thin wrapper over a Nym `MixnetClient`: one mix address.
pub struct NymTransport {
    client: MixnetClient,
    mode: DataMode,
    last_send: Option<Instant>,
}

impl NymTransport {
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
    /// of Sphinx encryption on top. Only the sender is ever asked to send.
    ///
    /// Sent as Nym's plain message type: just the frame. Despite its name,
    /// `ExposeSelfAddress` puts nothing about us in the packet — it means
    /// "no reply SURBs; the recipient must already know where to answer",
    /// which contacts do. The alternative, `IncludedSurbs::none()`, sends an
    /// anonymous message instead: a sender tag and SURB count on top, which
    /// push a full [`PAD_BLOCK`](crate::PAD_BLOCK) into a second packet.
    async fn send(&mut self, to: &MixAddress, payload: &[u8]) -> Result<()> {
        let recipient: Recipient =
            to.0.parse()
                .map_err(|e| anyhow!("invalid mix address {:?}: {e}", to.0))?;
        self.client
            .send_message(recipient, pad(payload)?, IncludedSurbs::ExposeSelfAddress)
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

    use nym_sphinx::message::NymMessage;
    use nym_sphinx::params::PacketSize;

    /// How many Sphinx packets Nym turns a `frame` into, the way its
    /// message preparer does.
    fn packets(frame: Vec<u8>) -> usize {
        let message = NymMessage::new_plain(frame);
        let per_packet = message.available_sphinx_plaintext_per_packet(PacketSize::RegularPacket);
        message
            .pad_to_full_packet_lengths(per_packet)
            .split_into_fragments(&mut rand08::thread_rng(), per_packet)
            .len()
    }

    #[test]
    fn padded_frames_fill_whole_packets() -> Result<()> {
        assert_eq!(packets(pad(b"hi")?), 1, "a short message is one packet");
        let blocks = crate::MAX_PAYLOAD.div_ceil(crate::PAD_BLOCK) + 1;
        for k in 1..=blocks {
            assert_eq!(packets(vec![0; k * crate::PAD_BLOCK]), k, "{k} blocks");
        }
        assert_eq!(
            packets(vec![0; crate::PAD_BLOCK + 1]),
            2,
            "PAD_BLOCK is the most"
        );
        Ok(())
    }

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
