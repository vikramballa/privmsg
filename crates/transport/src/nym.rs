//! The real transport: Nym mixnet clients, one per slot plus the sender.
//!
//! A Nym client's secrets — its keys, and the key it shares with its
//! gateway — never touch the disk here. They are kept in [`NymKeys`], which
//! privmsg stores inside its encrypted profile, so erasing the profile
//! takes them too. (Earlier versions let the Nym SDK keep them in files of
//! their own; [`adopt_nym_dir`] reads those once to move them in.)

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use nym_client_core_gateways_storage::{
    GatewayDetails, GatewayPublishedData, RawRegisteredGateway, RawRemoteGatewayDetails,
};
use nym_sdk::mixnet::{
    ed25519, x25519, ActiveGateway, BadGateway, ClientKeys, EmptyReplyStorage,
    EphemeralCredentialStorage, GatewayRegistration, GatewaysDetailsStore, IncludedSurbs, KeyStore,
    MixnetClient, MixnetClientBuilder, MixnetClientStorage, MixnetMessageSender, NymTopology,
    Recipient, StoragePaths,
};
use nym_sdk::{
    DebugConfig, NymApiTopologyProvider, NymApiTopologyProviderConfig, NymNetworkDetails,
    TopologyProvider,
};
use nym_sphinx::acknowledgements::AckKey;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::{sleep, Instant};
use zeroize::Zeroize;

use crate::{pad, unpad, DataMode, IncomingMessage, MixAddress, Network, NymKeys, Tor, Transport};

/// Gateways a new address tries before giving up.
const NEW_ADDRESS_TRIES: u32 = 3;

/// How long one attempt to reach the mixnet may take. Through Tor it
/// usually takes 10–30 s; a gateway that never answers would otherwise
/// hang forever.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(120);

/// The sender's name in [`NymKeys`]. Slot names are random hex, so they
/// can't collide with it.
const SENDER: &str = "sender";

/// The Nym mainnet. Each slot's client keys and gateway registration are
/// kept in `keys` under the slot's name, so its address survives restarts.
pub struct NymNetwork {
    keys: NymKeys,
    mode: DataMode,
    tor: Option<Tor>,
    topology: SharedTopology,
}

impl NymNetwork {
    pub fn new(keys: NymKeys, mode: DataMode) -> Self {
        Self {
            keys,
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
}

impl Network for NymNetwork {
    type Endpoint = NymTransport;

    /// A new slot registers with a gateway chosen uniformly at random by the
    /// SDK, so two slots of the same user don't share a gateway by design.
    async fn open(&self, slot: &str) -> Result<NymTransport> {
        if slot.is_empty() || slot == SENDER {
            return Err(anyhow!("invalid slot name {slot:?}"));
        }
        self.connect(slot, Role::Slot).await
    }

    async fn open_sender(&self) -> Result<NymTransport> {
        self.connect(SENDER, Role::Sender).await
    }

    fn forget(&self, slot: &str) -> Result<()> {
        self.keys.remove(slot);
        Ok(())
    }
}

impl NymNetwork {
    /// Connect to the Nym mainnet as the client `name`, keeping its keys
    /// and gateway registration in [`NymKeys`] so the overlay address
    /// survives restarts.
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
    async fn connect(&self, name: &str, role: Role) -> Result<NymTransport> {
        let fresh = !self.keys.contains(name);
        let tries = if fresh { NEW_ADDRESS_TRIES } else { 2 };
        let mut attempt = 1;
        loop {
            match self.connect_once(name, role).await {
                Err(e) if attempt < tries => {
                    if fresh {
                        tracing::warn!("new address failed ({e:#}); trying another gateway");
                        self.keys.remove(name);
                    } else {
                        tracing::warn!("connecting failed ({e:#}); trying again");
                        sleep(Duration::from_secs(3)).await;
                    }
                    attempt += 1;
                }
                Err(e) => {
                    if fresh {
                        // Keys no gateway knows are useless; don't keep them.
                        self.keys.remove(name);
                    }
                    return Err(e);
                }
                done => return done,
            }
        }
    }

    async fn connect_once(&self, name: &str, role: Role) -> Result<NymTransport> {
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
        let connecting = MixnetClientBuilder::new_with_storage(Kept::storage(name, &self.keys))
            .debug_config(debug)
            .force_tls(self.tor.is_some())
            .custom_topology_provider(Box::new(self.topology.clone()))
            .build()?
            .connect_to_mixnet();
        let client = tokio::time::timeout(CONNECT_TIMEOUT, connecting)
            .await
            .map_err(|_| {
                anyhow!(
                    "the gateway did not answer within {} s",
                    CONNECT_TIMEOUT.as_secs()
                )
            })?
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

    /// Flush pending sends, if anything was sent, then close the
    /// connection to the gateway. A slot (which never sends) closes at
    /// once, so it stops taking in messages nothing will read.
    pub async fn disconnect(self) {
        if self.last_send.is_some() {
            self.flush(Duration::from_secs(30)).await;
        }
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

    fn is_alive(&self) -> bool {
        !self.client.cancellation_token().is_cancelled()
    }
}

/// What a Nym client keeps: its own keys (empty until it first connects) and
/// its gateway registration. Stored in [`NymKeys`] as bincode.
#[derive(Default, Serialize, Deserialize)]
struct Secrets {
    identity: Vec<u8>,
    encryption: Vec<u8>,
    ack: Vec<u8>,
    gateway: Option<(RawRegisteredGateway, RawRemoteGatewayDetails)>,
}

impl Drop for Secrets {
    fn drop(&mut self) {
        self.identity.zeroize();
        self.encryption.zeroize();
        self.ack.zeroize();
        // The gateway's shared key wipes itself (RawRemoteGatewayDetails).
    }
}

impl Secrets {
    fn keys(&self) -> Result<ClientKeys, KeptError> {
        if self.identity.is_empty() {
            return Err(KeptError("no keys yet".into()));
        }
        let identity = ed25519::PrivateKey::from_bytes(&self.identity)?;
        let encryption = x25519::PrivateKey::from_bytes(&self.encryption)?;
        let ack = AckKey::try_from_bytes(&self.ack)?;
        Ok(ClientKeys::from_keys(
            identity.into(),
            encryption.into(),
            ack,
        ))
    }

    fn set_keys(&mut self, keys: &ClientKeys) {
        self.identity = keys.identity_keypair().private_key().to_bytes().to_vec();
        self.encryption = keys.encryption_keypair().private_key().to_bytes().to_vec();
        self.ack = keys.ack_key().to_bytes();
    }

    fn registration(&self) -> Result<Option<GatewayRegistration>, KeptError> {
        let Some((registered, details)) = &self.gateway else {
            return Ok(None);
        };
        let details = RawRemoteGatewayDetails {
            gateway_id_bs58: details.gateway_id_bs58.clone(),
            derived_aes256_gcm_siv_key: details.derived_aes256_gcm_siv_key.clone(),
            published_data: details.published_data.clone(),
        };
        Ok(Some(GatewayRegistration {
            details: GatewayDetails::Remote(details.try_into()?),
            registration_timestamp: registered.registration_timestamp,
        }))
    }

    fn set_registration(&mut self, registration: &GatewayRegistration) -> Result<(), KeptError> {
        let GatewayDetails::Remote(remote) = &registration.details else {
            return Err(KeptError("only remote gateways are supported".into()));
        };
        self.gateway = Some((registration.into(), remote.into()));
        Ok(())
    }

    /// The registration, if it is with `gateway_id`.
    fn registered_with(&self, gateway_id: &str) -> bool {
        self.gateway
            .as_ref()
            .is_some_and(|(r, _)| r.gateway_id_bs58 == gateway_id)
    }
}

/// One client's view of [`NymKeys`]: the entry `name`.
#[derive(Clone)]
struct Kept {
    name: String,
    keys: NymKeys,
}

impl Kept {
    /// Everything the Nym SDK needs to keep for the client `name`. Reply
    /// SURBs and bandwidth credentials are not used, so they are not kept.
    fn storage(name: &str, keys: &NymKeys) -> KeptStorage {
        let kept = Kept {
            name: name.to_string(),
            keys: keys.clone(),
        };
        KeptStorage {
            keys: kept.clone(),
            gateways: KeptGateways(kept),
            replies: EmptyReplyStorage::default(),
            credentials: EphemeralCredentialStorage::default(),
        }
    }

    fn read(&self) -> Result<Secrets, KeptError> {
        match self.keys.get(&self.name) {
            None => Ok(Secrets::default()),
            Some(bytes) => Ok(bincode::deserialize(&bytes)?),
        }
    }

    fn write(&self, secrets: &Secrets) -> Result<(), KeptError> {
        let bytes = bincode::serialize(secrets)?;
        self.keys.set(&self.name, bytes);
        Ok(())
    }
}

#[derive(Clone)]
struct KeptStorage {
    keys: Kept,
    gateways: KeptGateways,
    replies: EmptyReplyStorage,
    credentials: EphemeralCredentialStorage,
}

impl MixnetClientStorage for KeptStorage {
    type KeyStore = Kept;
    type ReplyStore = EmptyReplyStorage;
    type CredentialStore = EphemeralCredentialStorage;
    type GatewaysDetailsStore = KeptGateways;

    fn into_runtime_stores(
        self,
    ) -> (
        Self::ReplyStore,
        Self::CredentialStore,
        Self::GatewaysDetailsStore,
    ) {
        (self.replies, self.credentials, self.gateways)
    }

    fn key_store(&self) -> &Self::KeyStore {
        &self.keys
    }

    fn reply_store(&self) -> &Self::ReplyStore {
        &self.replies
    }

    fn credential_store(&self) -> &Self::CredentialStore {
        &self.credentials
    }

    fn gateway_details_store(&self) -> &Self::GatewaysDetailsStore {
        &self.gateways
    }
}

#[async_trait::async_trait]
impl KeyStore for Kept {
    type StorageError = KeptError;

    async fn load_keys(&self) -> Result<ClientKeys, KeptError> {
        self.read()?.keys()
    }

    async fn store_keys(&self, keys: &ClientKeys) -> Result<(), KeptError> {
        let mut secrets = self.read()?;
        secrets.set_keys(keys);
        self.write(&secrets)
    }
}

/// A client's gateway registration. privmsg's clients only ever register
/// with one gateway (their address names it), so that one is the active one.
#[derive(Clone)]
struct KeptGateways(Kept);

#[async_trait::async_trait]
impl GatewaysDetailsStore for KeptGateways {
    type StorageError = KeptError;

    async fn active_gateway(&self) -> Result<ActiveGateway, KeptError> {
        Ok(ActiveGateway {
            registration: self.0.read()?.registration()?,
        })
    }

    async fn set_active_gateway(&self, gateway_id: &str) -> Result<(), KeptError> {
        if self.0.read()?.registered_with(gateway_id) {
            Ok(())
        } else {
            Err(KeptError(format!(
                "not registered with gateway {gateway_id}"
            )))
        }
    }

    async fn all_gateways(&self) -> Result<Vec<GatewayRegistration>, KeptError> {
        Ok(self.0.read()?.registration()?.into_iter().collect())
    }

    async fn has_gateway_details(&self, gateway_id: &str) -> Result<bool, KeptError> {
        Ok(self.0.read()?.registered_with(gateway_id))
    }

    async fn load_gateway_details(
        &self,
        gateway_id: &str,
    ) -> Result<GatewayRegistration, KeptError> {
        let secrets = self.0.read()?;
        match secrets.registration()? {
            Some(r) if secrets.registered_with(gateway_id) => Ok(r),
            _ => Err(KeptError(format!(
                "not registered with gateway {gateway_id}"
            ))),
        }
    }

    async fn store_gateway_details(&self, details: &GatewayRegistration) -> Result<(), KeptError> {
        let mut secrets = self.0.read()?;
        secrets.set_registration(details)?;
        self.0.write(&secrets)
    }

    async fn update_gateway_published_data(
        &self,
        gateway_id: &ed25519::PublicKey,
        published_data: &GatewayPublishedData,
    ) -> Result<(), KeptError> {
        let mut secrets = self.0.read()?;
        if let Some((_, details)) = secrets
            .gateway
            .as_mut()
            .filter(|(r, _)| r.gateway_id_bs58 == gateway_id.to_base58_string())
        {
            details.published_data = published_data.into();
            self.0.write(&secrets)?;
        }
        Ok(())
    }

    async fn remove_gateway_details(&self, gateway_id: &str) -> Result<(), KeptError> {
        let mut secrets = self.0.read()?;
        if secrets.registered_with(gateway_id) {
            secrets.gateway = None;
            self.0.write(&secrets)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct KeptError(String);

impl std::fmt::Display for KeptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "kept Nym keys: {}", self.0)
    }
}

impl std::error::Error for KeptError {}

/// Errors from Nym's key and gateway types, as a [`KeptError`].
macro_rules! kept_error_from {
    ($($error:ty),*) => {$(
        impl From<$error> for KeptError {
            fn from(e: $error) -> Self {
                KeptError(e.to_string())
            }
        }
    )*};
}

kept_error_from!(
    BadGateway,
    bincode::Error,
    ed25519::Ed25519RecoveryError,
    x25519::KeyRecoveryError,
    nym_sphinx::acknowledgements::key::AckKeyConversionError
);

/// Read the Nym client kept in files in `dir` — how versions before the
/// keys moved into the profile stored them — as bytes for [`NymKeys`].
/// `None` if there are no keys there.
pub async fn adopt_nym_dir(dir: &Path) -> Result<Option<Vec<u8>>> {
    let paths = StoragePaths::new_from_dir(dir)?;
    let Ok(keys) = KeyStore::load_keys(&paths.on_disk_key_storage_spec()).await else {
        return Ok(None);
    };
    let mut secrets = Secrets::default();
    secrets.set_keys(&keys);
    let gateways = paths
        .on_disk_gateway_details_storage()
        .await
        .context("read the gateway registration")?;
    if let Some(registration) = gateways.active_gateway().await?.registration {
        secrets
            .set_registration(&registration)
            .map_err(|e| anyhow!("{e}"))?;
    }
    Ok(Some(bincode::serialize(&secrets)?))
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

    #[tokio::test]
    async fn kept_keys_and_registration_round_trip() -> Result<()> {
        let keys = NymKeys::default();
        let kept = Kept::storage("ab12", &keys);
        assert!(kept.key_store().load_keys().await.is_err(), "none yet");
        assert!(keys.take_changes().is_none());

        let client = ClientKeys::generate_new(&mut rand08::rngs::OsRng);
        kept.key_store().store_keys(&client).await?;
        let saved = keys.take_changes().expect("changed");
        assert!(saved.contains_key("ab12"));

        // A fresh view of the saved bytes gives the same keys back.
        let again = Kept::storage("ab12", &NymKeys::new(saved));
        let loaded = again.key_store().load_keys().await?;
        assert_eq!(
            loaded.identity_keypair().public_key(),
            client.identity_keypair().public_key()
        );
        assert_eq!(
            loaded.encryption_keypair().public_key(),
            client.encryption_keypair().public_key()
        );
        assert_eq!(loaded.ack_key().to_bytes(), client.ack_key().to_bytes());
        let active = again.gateway_details_store().active_gateway().await?;
        assert!(active.registration.is_none(), "no gateway yet");
        Ok(())
    }

    #[test]
    fn the_sender_name_is_not_a_slot() {
        let net = NymNetwork::new(NymKeys::default(), DataMode::Saver);
        let rt = tokio::runtime::Runtime::new().unwrap();
        assert!(rt.block_on(net.open(SENDER)).is_err());
        assert!(rt.block_on(net.open("")).is_err());
    }
}
