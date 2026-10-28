//! Layer 1 — Content encryption (MLS / RFC 9420 via OpenMLS).
//!
//! This crate knows nothing about the network. It turns plaintext into
//! MLS ciphertext and back. The bytes it emits are what the transport
//! layer (`privmsg-transport`) carries across the Nym mixnet, so by the
//! time a message leaves the device it is already end-to-end encrypted
//! with forward secrecy and post-compromise security.
//!
//! Scope of Phase 1: a two-party group (Alice + Bob). MLS is a *group*
//! protocol via TreeKEM, so extending this to N members later is adding
//! members, not rewriting — that is one of the reasons we chose MLS over
//! a pairwise double-ratchet.
//!
//! API note: OpenMLS evolves method signatures across minor versions.
//! This targets the 0.6 line. If `cargo check` flags a signature, the
//! shape of the flow below is still correct — adjust the call, not the
//! design.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
use openmls_traits::random::OpenMlsRand;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};

/// The mandatory-to-implement ciphersuite: X25519 + AES-128-GCM + SHA-256 + Ed25519.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// One participant's long-lived crypto state: the OpenMLS provider (key
/// store + crypto backend) plus an original signature keypair and
/// credential. In a real client the provider is backed by SQLCipher on
/// disk; here it is in-memory.
///
/// Unlinkability: every key package and every group we create gets a fresh
/// signature key and a fresh random credential label (a *persona*), kept in
/// the same store. Contacts, or anyone holding two of our invites, see
/// nothing in MLS that ties our conversations together. The original
/// signer only remains for groups made before personas existed.
pub struct Identity {
    pub provider: OpenMlsRustCrypto,
    pub signer: SignatureKeyPair,
    pub credential: CredentialWithKey,
    label: Vec<u8>,
}

/// Everything needed to rebuild an [`Identity`]: its label, the public half
/// of its signature key (the private half lives in the storage map), and the
/// full OpenMLS key/group store. OpenMLS 0.6 writes group state into the
/// store on every operation, so this one snapshot also carries every group.
#[derive(Serialize, Deserialize)]
struct IdentitySnapshot {
    label: Vec<u8>,
    signer_public: Vec<u8>,
    storage: HashMap<Vec<u8>, Vec<u8>>,
}

impl Identity {
    /// Create a fresh identity for `name`.
    ///
    /// IMPORTANT (metadata hygiene): `name` here is a *local* label only.
    /// It must never become a stable network identifier — Layer 3's
    /// no-identifier handshake (see docs/ARCHITECTURE.md §4) is what keeps
    /// identities from being linkable across conversations. Do not leak
    /// this string onto the wire.
    pub fn new(name: &str) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();

        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|e| anyhow!("signature keypair: {e:?}"))?;
        signer
            .store(provider.storage())
            .map_err(|e| anyhow!("store signer: {e:?}"))?;

        Ok(Self::assemble(provider, signer, name.as_bytes().to_vec()))
    }

    fn assemble(provider: OpenMlsRustCrypto, signer: SignatureKeyPair, label: Vec<u8>) -> Self {
        let credential = credential(label.clone(), &signer);
        Self {
            provider,
            signer,
            credential,
            label,
        }
    }

    /// A fresh signature key and credential with a random label, stored so
    /// that [`Identity::signer_for`] finds the key again after a restart.
    fn new_persona(&self) -> Result<(SignatureKeyPair, CredentialWithKey)> {
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|e| anyhow!("signature keypair: {e:?}"))?;
        signer
            .store(self.provider.storage())
            .map_err(|e| anyhow!("store signer: {e:?}"))?;
        let random = self
            .provider
            .rand()
            .random_vec(16)
            .map_err(|e| anyhow!("random label: {e:?}"))?;
        let label = random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let credential = credential(label.into_bytes(), &signer);
        Ok((signer, credential))
    }

    /// The stored signature key whose public half is `public`.
    fn signer_for(&self, public: &[u8]) -> Result<SignatureKeyPair> {
        SignatureKeyPair::read(
            self.provider.storage(),
            public,
            CIPHERSUITE.signature_algorithm(),
        )
        .ok_or_else(|| anyhow!("signature key for this conversation is missing"))
    }

    /// Serialize this identity, including every group it belongs to, so it
    /// can be written to disk. The output contains private keys: the caller
    /// must encrypt it before it touches storage.
    pub fn snapshot(&self) -> Result<Vec<u8>> {
        let storage = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| anyhow!("key store lock poisoned"))?
            .clone();
        let snap = IdentitySnapshot {
            label: self.label.clone(),
            signer_public: self.signer.to_public_vec(),
            storage,
        };
        bincode::serialize(&snap).map_err(|e| anyhow!("serialize identity: {e}"))
    }

    /// Rebuild an identity from [`Identity::snapshot`] output.
    pub fn restore(bytes: &[u8]) -> Result<Self> {
        let snap: IdentitySnapshot =
            bincode::deserialize(bytes).map_err(|e| anyhow!("deserialize identity: {e}"))?;

        let provider = OpenMlsRustCrypto::default();
        *provider
            .storage()
            .values
            .write()
            .map_err(|_| anyhow!("key store lock poisoned"))? = snap.storage;

        let signer = SignatureKeyPair::read(
            provider.storage(),
            &snap.signer_public,
            CIPHERSUITE.signature_algorithm(),
        )
        .ok_or_else(|| anyhow!("signature key missing from snapshot"))?;

        Ok(Self::assemble(provider, signer, snap.label))
    }

    /// Publish a KeyPackage — the public artifact another party consumes
    /// to add us to a group. In Phase 1 we hand it over directly; later it
    /// is fetched through the metadata-private directory, never a lookup
    /// that reveals who is adding whom. Each one carries a new persona.
    pub fn key_package(&self) -> Result<KeyPackage> {
        let (signer, credential) = self.new_persona()?;
        let bundle = KeyPackage::builder()
            .build(CIPHERSUITE, &self.provider, &signer, credential)
            .map_err(|e| anyhow!("key package: {e:?}"))?;
        Ok(bundle.key_package().clone())
    }
}

fn credential(label: Vec<u8>, signer: &SignatureKeyPair) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(label).into(),
        signature_key: signer.public().into(),
    }
}

/// Wire encoding of a KeyPackage (TLS presentation language, per RFC 9420).
pub fn encode_key_package(kp: &KeyPackage) -> Result<Vec<u8>> {
    kp.tls_serialize_detached()
        .map_err(|e| anyhow!("serialize key package: {e:?}"))
}

/// Parse a KeyPackage received from someone else and verify its signature
/// and ciphersuite before it is used. Rejects anything malformed.
pub fn decode_key_package(bytes: &[u8]) -> Result<KeyPackage> {
    let kp_in = KeyPackageIn::tls_deserialize_exact(bytes)
        .map_err(|e| anyhow!("deserialize key package: {e:?}"))?;
    let kp = kp_in
        .validate(&RustCrypto::default(), ProtocolVersion::Mls10)
        .map_err(|e| anyhow!("invalid key package: {e:?}"))?;
    if kp.ciphersuite() != CIPHERSUITE {
        return Err(anyhow!("unsupported ciphersuite {:?}", kp.ciphersuite()));
    }
    // The leaf's key is only reachable through its encoding, which ends in
    // the 32 key bytes.
    let leaf_key = kp
        .leaf_node()
        .encryption_key()
        .tls_serialize_detached()
        .map_err(|e| anyhow!("encode leaf key: {e:?}"))?;
    let tail = |b: &[u8]| b[b.len().saturating_sub(32)..].to_vec();
    if !contributory(kp.hpke_init_key().as_slice()) || !contributory(&tail(&leaf_key)) {
        return Err(anyhow!("invalid key package: weak encryption key"));
    }
    Ok(kp)
}

/// Whether X25519 with `public` yields a secret that depends on our key.
/// The low-order points make it all zeros for every private key, and
/// hpke-rs 0.2 doesn't refuse them as RFC 9180 requires (RUSTSEC-2026-0072):
/// a key package with one would have us encrypt the Welcome under a key
/// anyone can compute.
fn contributory(public: &[u8]) -> bool {
    let Ok(point) = <[u8; 32]>::try_from(public) else {
        return false;
    };
    // Clamping clears the cofactor, so any fixed scalar exposes them.
    x25519_dalek::x25519([0x42; 32], point) != [0u8; 32]
}

/// Read the group id from an MLS protocol message without decrypting it, so
/// the receiver can route the message to the right [`Session`]. The group id
/// is in the clear in MLS framing; it is visible only to the recipient here,
/// because the mixnet wraps the whole message in Sphinx encryption.
pub fn message_group_id(ciphertext: &[u8]) -> Result<Vec<u8>> {
    let msg_in = MlsMessageIn::tls_deserialize_exact(ciphertext)
        .map_err(|e| anyhow!("deserialize message: {e:?}"))?;
    let protocol_msg: ProtocolMessage = msg_in
        .try_into_protocol_message()
        .map_err(|e| anyhow!("not a protocol message: {e:?}"))?;
    Ok(protocol_msg.group_id().as_slice().to_vec())
}

/// A live MLS session wrapping one `MlsGroup`, with the signature key of
/// our leaf in it.
pub struct Session {
    group: MlsGroup,
    signer: SignatureKeyPair,
}

impl Session {
    /// Alice creates the group.
    ///
    /// We enable the ratchet-tree extension so the `Welcome` carries the
    /// group's public tree in-band. The alternative is shipping the tree
    /// out of band to each joiner; in-band is simpler for Phase 1 and the
    /// tree is public anyway (it contains no secrets).
    pub fn create(id: &Identity) -> Result<Self> {
        let config = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let (signer, credential) = id.new_persona()?;
        let group = MlsGroup::new(&id.provider, &signer, &config, credential)
            .map_err(|e| anyhow!("create group: {e:?}"))?;
        Ok(Self { group, signer })
    }

    /// Reopen a group this identity already belongs to (e.g. after
    /// [`Identity::restore`]).
    pub fn load(id: &Identity, group_id: &[u8]) -> Result<Self> {
        let group = MlsGroup::load(id.provider.storage(), &GroupId::from_slice(group_id))
            .map_err(|e| anyhow!("load group: {e:?}"))?
            .ok_or_else(|| anyhow!("no such group in storage"))?;
        Self::with_own_signer(id, group)
    }

    /// Pair `group` with the stored key our leaf in it was signed with.
    fn with_own_signer(id: &Identity, group: MlsGroup) -> Result<Self> {
        let leaf = group
            .own_leaf_node()
            .ok_or_else(|| anyhow!("we are not a member of this group"))?;
        let signer = id.signer_for(leaf.signature_key().as_slice())?;
        Ok(Self { group, signer })
    }

    /// A number both people in this conversation see only if nobody sits
    /// in the middle: derived from the group's epoch authenticator, which
    /// covers both members' keys. Compare it in person or over a call.
    pub fn safety_number(&self) -> String {
        let digest = self.group.epoch_authenticator().as_slice();
        digest
            .chunks(3)
            .take(6)
            .map(|c| {
                let n = c.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b));
                format!("{:05}", n % 100_000)
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// This group's id, used to route incoming messages.
    pub fn group_id(&self) -> Vec<u8> {
        self.group.group_id().as_slice().to_vec()
    }

    /// Erase this group's state from the identity's storage (e.g. a join
    /// that was refused).
    pub fn delete(mut self, id: &Identity) -> Result<()> {
        self.group
            .delete(id.provider.storage())
            .map_err(|e| anyhow!("delete group: {e:?}"))
    }

    /// Alice adds Bob via his KeyPackage.
    ///
    /// Returns the serialized `Welcome` message. Alice sends it to Bob
    /// over the transport; Bob calls [`Session::join`] with it. The commit
    /// is merged into Alice's local state immediately.
    pub fn add_member(&mut self, id: &Identity, member_kp: KeyPackage) -> Result<Vec<u8>> {
        let (_commit, welcome, _group_info) = self
            .group
            .add_members(&id.provider, &self.signer, &[member_kp])
            .map_err(|e| anyhow!("add member: {e:?}"))?;

        self.group
            .merge_pending_commit(&id.provider)
            .map_err(|e| anyhow!("merge commit: {e:?}"))?;

        let bytes = welcome
            .tls_serialize_detached()
            .map_err(|e| anyhow!("serialize welcome: {e:?}"))?;
        Ok(bytes)
    }

    /// Bob joins from the serialized `Welcome` Alice sent.
    ///
    /// The group creator picks the group id, so a Welcome reusing the id of
    /// a group we are already in is refused: joining would overwrite that
    /// conversation's state.
    pub fn join(id: &Identity, welcome_bytes: &[u8]) -> Result<Self> {
        let msg_in = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|e| anyhow!("deserialize welcome: {e:?}"))?;

        let welcome = match msg_in.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(anyhow!("expected a Welcome message")),
        };

        let processed = ProcessedWelcome::new_from_welcome(
            &id.provider,
            &MlsGroupJoinConfig::default(),
            welcome,
        )
        .map_err(|e| anyhow!("process welcome: {e:?}"))?;
        let group_id = processed.unverified_group_info().group_id().clone();
        if MlsGroup::load(id.provider.storage(), &group_id)
            .map_err(|e| anyhow!("check existing group: {e:?}"))?
            .is_some()
        {
            return Err(anyhow!("welcome reuses the id of an existing group"));
        }
        let staged = processed
            .into_staged_welcome(&id.provider, None) // ratchet tree is in-band
            .map_err(|e| anyhow!("stage welcome: {e:?}"))?;

        let group = staged
            .into_group(&id.provider)
            .map_err(|e| anyhow!("into group: {e:?}"))?;
        Self::with_own_signer(id, group)
    }

    /// Encrypt an application message. The returned bytes are what crosses
    /// the mixnet — opaque ciphertext to every relay and to the network.
    pub fn encrypt(&mut self, id: &Identity, plaintext: &[u8]) -> Result<Vec<u8>> {
        let out = self
            .group
            .create_message(&id.provider, &self.signer, plaintext)
            .map_err(|e| anyhow!("create message: {e:?}"))?;
        out.tls_serialize_detached()
            .map_err(|e| anyhow!("serialize message: {e:?}"))
    }

    /// Decrypt an application message received from the transport layer.
    pub fn decrypt(&mut self, id: &Identity, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let msg_in = MlsMessageIn::tls_deserialize_exact(ciphertext)
            .map_err(|e| anyhow!("deserialize message: {e:?}"))?;

        let protocol_msg: ProtocolMessage = msg_in
            .try_into_protocol_message()
            .map_err(|e| anyhow!("not a protocol message: {e:?}"))?;

        let processed = self
            .group
            .process_message(&id.provider, protocol_msg)
            .map_err(|e| anyhow!("process message: {e:?}"))?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(app.into_bytes()),
            _ => Err(anyhow!("expected an application message")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end: Alice creates a group, adds Bob, they exchange an
    /// encrypted message both ways. No network involved — this proves the
    /// content layer in isolation.
    #[test]
    fn two_party_roundtrip() -> Result<()> {
        let alice = Identity::new("alice-local-label")?;
        let bob = Identity::new("bob-local-label")?;

        let bob_kp = bob.key_package()?;

        let mut alice_session = Session::create(&alice)?;
        let welcome = alice_session.add_member(&alice, bob_kp)?;
        let mut bob_session = Session::join(&bob, &welcome)?;

        let ct = alice_session.encrypt(&alice, b"hello bob")?;
        let pt = bob_session.decrypt(&bob, &ct)?;
        assert_eq!(pt, b"hello bob");

        let ct2 = bob_session.encrypt(&bob, b"hi alice")?;
        let pt2 = alice_session.decrypt(&alice, &ct2)?;
        assert_eq!(pt2, b"hi alice");

        Ok(())
    }

    /// Alice + Bob joined and talking, with the key package going over the
    /// wire encoding the way the app sends it.
    fn pair() -> Result<(Identity, Session, Identity, Session)> {
        let alice = Identity::new("alice-local-label")?;
        let bob = Identity::new("bob-local-label")?;
        let bob_kp = decode_key_package(&encode_key_package(&bob.key_package()?)?)?;
        let mut alice_session = Session::create(&alice)?;
        let welcome = alice_session.add_member(&alice, bob_kp)?;
        let bob_session = Session::join(&bob, &welcome)?;
        Ok((alice, alice_session, bob, bob_session))
    }

    #[test]
    fn many_messages_both_ways() -> Result<()> {
        let (alice, mut a, bob, mut b) = pair()?;
        for i in 0..50 {
            let msg = format!("message {i}");
            let ct = a.encrypt(&alice, msg.as_bytes())?;
            assert_eq!(b.decrypt(&bob, &ct)?, msg.as_bytes());
            let ct = b.encrypt(&bob, msg.as_bytes())?;
            assert_eq!(a.decrypt(&alice, &ct)?, msg.as_bytes());
        }
        Ok(())
    }

    #[test]
    fn out_of_order_delivery_within_tolerance() -> Result<()> {
        // The mixnet reorders packets; MLS must cope with small reordering.
        let (alice, mut a, bob, mut b) = pair()?;
        let first = a.encrypt(&alice, b"first")?;
        let second = a.encrypt(&alice, b"second")?;
        assert_eq!(b.decrypt(&bob, &second)?, b"second");
        assert_eq!(b.decrypt(&bob, &first)?, b"first");
        Ok(())
    }

    #[test]
    fn tampered_ciphertext_is_rejected() -> Result<()> {
        let (alice, mut a, bob, mut b) = pair()?;
        let mut ct = a.encrypt(&alice, b"do not touch")?;
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(b.decrypt(&bob, &ct).is_err());
        Ok(())
    }

    #[test]
    fn replayed_message_is_rejected() -> Result<()> {
        let (alice, mut a, bob, mut b) = pair()?;
        let ct = a.encrypt(&alice, b"once")?;
        assert_eq!(b.decrypt(&bob, &ct)?, b"once");
        assert!(b.decrypt(&bob, &ct).is_err());
        Ok(())
    }

    #[test]
    fn outsider_cannot_join_or_decrypt() -> Result<()> {
        let alice = Identity::new("alice-local-label")?;
        let bob = Identity::new("bob-local-label")?;
        let eve = Identity::new("eve-local-label")?;
        let mut a = Session::create(&alice)?;
        let welcome = a.add_member(&alice, bob.key_package()?)?;
        // The Welcome is encrypted to Bob's key package; Eve can't use it.
        assert!(Session::join(&eve, &welcome).is_err());
        Ok(())
    }

    #[test]
    fn group_id_is_readable_without_decrypting() -> Result<()> {
        let (alice, mut a, _bob, b) = pair()?;
        let ct = a.encrypt(&alice, b"route me")?;
        assert_eq!(message_group_id(&ct)?, a.group_id());
        assert_eq!(a.group_id(), b.group_id());
        assert!(message_group_id(b"not mls").is_err());
        Ok(())
    }

    #[test]
    fn welcome_for_an_existing_group_is_refused() -> Result<()> {
        // Mallory holds one of Bob's key packages and builds a group whose id
        // collides with Bob's conversation with Alice.
        let (_alice, a, bob, _b) = pair()?;
        let mallory = Identity::new("mallory-local-label")?;
        let config = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new_with_group_id(
            &mallory.provider,
            &mallory.signer,
            &config,
            GroupId::from_slice(&a.group_id()),
            mallory.credential.clone(),
        )
        .map_err(|e| anyhow!("{e:?}"))?;
        let signer = mallory.signer_for(mallory.signer.public())?;
        let mut evil = Session { group, signer };
        let welcome = evil.add_member(&mallory, bob.key_package()?)?;
        let err = Session::join(&bob, &welcome).err().unwrap();
        assert!(err.to_string().contains("existing group"));
        assert!(Session::load(&bob, &a.group_id()).is_ok(), "untouched");
        Ok(())
    }

    #[test]
    fn invites_and_conversations_cannot_be_linked_by_key() -> Result<()> {
        let bob = Identity::new("bob-local-label")?;
        let (kp1, kp2) = (bob.key_package()?, bob.key_package()?);
        let key = |kp: &KeyPackage| kp.leaf_node().signature_key().as_slice().to_vec();
        let label = |kp: &KeyPackage| kp.leaf_node().credential().serialized_content().to_vec();
        assert_ne!(key(&kp1), key(&kp2), "two invites, two keys");
        assert_ne!(label(&kp1), label(&kp2), "and two labels");
        assert_ne!(key(&kp1), bob.signer.public(), "not the original key");

        // Two groups Bob starts himself use different keys too.
        let (one, two) = (Session::create(&bob)?, Session::create(&bob)?);
        let own = |s: &Session| {
            s.group
                .own_leaf_node()
                .unwrap()
                .signature_key()
                .as_slice()
                .to_vec()
        };
        assert_ne!(own(&one), own(&two));
        Ok(())
    }

    #[test]
    fn both_sides_see_the_same_safety_number() -> Result<()> {
        let (_alice, a, _bob, b) = pair()?;
        assert_eq!(a.safety_number(), b.safety_number());
        assert_eq!(a.safety_number().len(), 6 * 5 + 5);
        // A different conversation (say, with someone in the middle) differs.
        let (_c, c, _d, _) = pair()?;
        assert_ne!(a.safety_number(), c.safety_number());
        Ok(())
    }

    #[test]
    fn conversations_from_before_personas_still_work() -> Result<()> {
        // Made the old way: Alice's group and Bob's key package both signed
        // with the identity's original key.
        let alice = Identity::new("alice-local-label")?;
        let bob = Identity::new("bob-local-label")?;
        let config = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new(
            &alice.provider,
            &alice.signer,
            &config,
            alice.credential.clone(),
        )
        .map_err(|e| anyhow!("{e:?}"))?;
        let mut a = Session {
            group,
            signer: alice.signer_for(alice.signer.public())?,
        };
        let old_kp = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &bob.provider,
                &bob.signer,
                bob.credential.clone(),
            )
            .map_err(|e| anyhow!("{e:?}"))?;
        let welcome = a.add_member(&alice, old_kp.key_package().clone())?;
        let b = Session::join(&bob, &welcome)?;

        let group_id = a.group_id();
        let alice = Identity::restore(&alice.snapshot()?)?;
        let bob = Identity::restore(&bob.snapshot()?)?;
        let (mut a, mut b) = (Session::load(&alice, &group_id)?, {
            drop(b);
            Session::load(&bob, &group_id)?
        });
        let ct = a.encrypt(&alice, b"still works")?;
        assert_eq!(b.decrypt(&bob, &ct)?, b"still works");
        let ct = b.encrypt(&bob, b"both ways")?;
        assert_eq!(a.decrypt(&alice, &ct)?, b"both ways");
        Ok(())
    }

    #[test]
    fn low_order_keys_are_refused() -> Result<()> {
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(!contributory(&[0u8; 32]), "the zero point");
        assert!(!contributory(&one), "a point of order 4");
        assert!(!contributory(&[7u8; 31]), "wrong length");
        let kp = Identity::new("x")?.key_package()?;
        assert!(contributory(kp.hpke_init_key().as_slice()), "a real key");
        assert!(decode_key_package(&encode_key_package(&kp)?).is_ok());
        Ok(())
    }

    #[test]
    fn garbage_key_package_is_rejected() {
        assert!(decode_key_package(b"").is_err());
        assert!(decode_key_package(&[0u8; 300]).is_err());
    }

    #[test]
    fn snapshot_restore_keeps_groups_working() -> Result<()> {
        let (alice, mut a, bob, mut b) = pair()?;
        let ct = a.encrypt(&alice, b"before restart")?;
        assert_eq!(b.decrypt(&bob, &ct)?, b"before restart");

        let group_id = a.group_id();
        let alice = Identity::restore(&alice.snapshot()?)?;
        let bob = Identity::restore(&bob.snapshot()?)?;
        let mut a = Session::load(&alice, &group_id)?;
        let mut b = Session::load(&bob, &group_id)?;

        let ct = a.encrypt(&alice, b"after restart")?;
        assert_eq!(b.decrypt(&bob, &ct)?, b"after restart");
        let ct = b.encrypt(&bob, b"still here")?;
        assert_eq!(a.decrypt(&alice, &ct)?, b"still here");
        Ok(())
    }

    #[test]
    fn join_after_restart_uses_stored_key_package() -> Result<()> {
        // Bob publishes an invite, quits, and the Welcome arrives later.
        let alice = Identity::new("alice-local-label")?;
        let bob = Identity::new("bob-local-label")?;
        let kp = bob.key_package()?;
        let bob = Identity::restore(&bob.snapshot()?)?;

        let mut a = Session::create(&alice)?;
        let welcome = a.add_member(&alice, kp)?;
        let mut b = Session::join(&bob, &welcome)?;
        let ct = a.encrypt(&alice, b"welcome back")?;
        assert_eq!(b.decrypt(&bob, &ct)?, b"welcome back");
        Ok(())
    }

    #[test]
    fn deleted_group_cannot_be_loaded() -> Result<()> {
        let (_alice, _a, bob, b) = pair()?;
        let group_id = b.group_id();
        b.delete(&bob)?;
        assert!(Session::load(&bob, &group_id).is_err());
        Ok(())
    }

    #[test]
    fn load_unknown_group_fails() -> Result<()> {
        let alice = Identity::new("alice-local-label")?;
        assert!(Session::load(&alice, b"no-such-group").is_err());
        Ok(())
    }
}
