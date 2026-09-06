//! Pure-Rust MLS engine — no FFI types, fully testable.

use ed25519_dalek::SigningKey;
use mls_rs::client_builder::{
    BaseInMemoryConfig, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider,
    WithKeyPackageRepo, WithMlsRules,
};
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::BasicCredential;
use mls_rs::mls_rules::DefaultMlsRules;
use mls_rs::{CipherSuite, Client, ExtensionList, Group, MlsMessage};
use mls_rs_core::crypto::{SignaturePublicKey, SignatureSecretKey};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

use crate::credential::{AirdressIdentity, AirdressIdentityProvider, RootKeyLookup};
use crate::storage::{
    DEFAULT_MAX_EPOCH_RETENTION, SealedGroupStore, SealedKeyPackageStore, SealedStore,
};

const CIPHER_SUITE: CipherSuite = CipherSuite::CURVE25519_CHACHA;

/// Why an engine operation failed.
///
/// Every arm but [`EngineError::EpochUnavailable`] is the historical
/// string, verbatim: `Display` for `Other` renders the message and
/// nothing else, so callers (and the FFI layer) that matched on those
/// strings keep working.
///
/// `EpochUnavailable` exists because "this message is from an epoch we
/// deliberately dropped" and "this message is corrupt" need different
/// answers (SPEC-061 FR-22). The first routes to catch-up; the second
/// is a hard failure. Carrying them both as one opaque decrypt error
/// leaves the client showing a mystery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    /// The message belongs to an epoch whose record has been trimmed
    /// out of the sealed store by the retention bound (FR-21). Never
    /// raised for an epoch that is merely in the *future* — that is a
    /// different condition with a different remedy.
    ///
    /// Carries no key material, per SPEC-061 NFR-6.
    EpochUnavailable {
        requested: u64,
        oldest_retained: Option<u64>,
    },
    /// Anything else, rendered exactly as it always was.
    Other(String),
}

impl core::fmt::Display for EngineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            // One sentence, matching the `credential.rs` discipline.
            Self::EpochUnavailable { .. } => {
                write!(
                    f,
                    "this message is older than the keys still on this device"
                )
            }
            Self::Other(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<String> for EngineError {
    fn from(msg: String) -> Self {
        Self::Other(msg)
    }
}

impl From<&str> for EngineError {
    fn from(msg: &str) -> Self {
        Self::Other(msg.to_owned())
    }
}

/// Pool size established at first init, matching the operator-side
/// KeyPackage count. A package whose private half is lost is a
/// Welcome the client can never join, so the private halves (and the
/// publishable public messages) persist through the sealed store.
pub const INITIAL_KEY_PACKAGE_POOL: usize = 16;

type MlsConfig = WithIdentityProvider<
    AirdressIdentityProvider,
    WithCryptoProvider<
        RustCryptoProvider,
        WithMlsRules<
            DefaultMlsRules,
            WithGroupStateStorage<
                SealedGroupStore,
                WithKeyPackageRepo<SealedKeyPackageStore, BaseInMemoryConfig>,
            >,
        >,
    >,
>;

pub struct StartGroupOutcome {
    pub group_id: Vec<u8>,
    pub welcome: Vec<u8>,
    pub first_application: Vec<u8>,
}

/// Unique-enough suffix for per-test state directories.
#[cfg(test)]
fn uuid_like() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

pub struct MlsEngine {
    client: Client<MlsConfig>,
    public_key: Vec<u8>,
    identity_provider: AirdressIdentityProvider,
    key_packages: SealedKeyPackageStore,
    /// A second handle on the same sealed group store `mls-rs` writes
    /// through, so the engine can ask which epochs survived the
    /// retention trim (SPEC-061 FR-22) without decoding the record.
    groups: SealedGroupStore,
}

impl MlsEngine {
    /// Test-only constructor with a fresh random session seed and a
    /// throwaway identity. Production callers must supply the seed and
    /// identity material from the host's secure storage via
    /// [`MlsEngine::from_seed`] — a per-instantiation random seed is
    /// exactly the bug that made pre-restart state impossible to
    /// decrypt.
    #[cfg(test)]
    pub fn new(airdress: &str) -> Result<Self, String> {
        use chacha20poly1305::aead::OsRng;
        use chacha20poly1305::aead::rand_core::RngCore;
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let root = SigningKey::from_bytes(&[7u8; 32]);
        let delegation = crate::credential::test_support::signed_delegation_json(
            &root,
            airdress,
            &SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
        );
        Self::from_seed(
            airdress,
            &seed,
            &root.verifying_key().to_bytes(),
            &delegation,
            std::env::temp_dir()
                .join(format!("airdress-mls-test-{}", uuid_like()))
                .to_str()
                .ok_or("temp dir not utf-8")?,
            &[9u8; 32],
        )
    }

    /// Construct the engine from host-supplied identity material.
    ///
    /// `seed` is the DEVICE SESSION signing seed, never the airdress
    /// root private key — the root must not cross into this crate
    /// (it signs delegations at enrollment/pairing time only).
    /// `root_public_key` and `delegation_json` describe this device's
    /// identity chain; `state_dir`/`state_key` locate and seal the
    /// on-disk MLS state.
    pub fn from_seed(
        airdress: &str,
        seed: &[u8; 32],
        root_public_key: &[u8; 32],
        delegation_json: &str,
        state_dir: &str,
        state_key: &[u8; 32],
    ) -> Result<Self, String> {
        Self::from_seed_with_retention(
            airdress,
            seed,
            root_public_key,
            delegation_json,
            state_dir,
            state_key,
            DEFAULT_MAX_EPOCH_RETENTION,
        )
    }

    /// [`MlsEngine::from_seed`] with an explicit epoch-retention bound
    /// (SPEC-061 FR-23). Production goes through `from_seed`, which
    /// supplies [`DEFAULT_MAX_EPOCH_RETENTION`] — the same default the
    /// operator's in-process agent engine uses, so forward secrecy at
    /// the storage layer is not a function of which binary ran.
    #[allow(clippy::too_many_arguments)]
    pub fn from_seed_with_retention(
        airdress: &str,
        seed: &[u8; 32],
        root_public_key: &[u8; 32],
        delegation_json: &str,
        state_dir: &str,
        state_key: &[u8; 32],
        max_epoch_retention: usize,
    ) -> Result<Self, String> {
        let delegation: serde_json::Value = serde_json::from_str(delegation_json)
            .map_err(|e| format!("delegation is not valid JSON: {e}"))?;
        let serde_json::Value::Object(delegation) = delegation else {
            return Err("delegation is not a JSON object".to_owned());
        };
        if state_dir.is_empty() {
            return Err("state_dir is empty".to_owned());
        }
        let signing_key = SigningKey::from_bytes(seed);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();

        let secret_key = SignatureSecretKey::from(signing_key.to_keypair_bytes().to_vec());
        let sig_pub = SignaturePublicKey::from(signing_key.verifying_key().to_bytes().to_vec());

        // Identity bytes carry the full chain — airdress, root public
        // key, and the root-signed delegation — not just the airdress.
        let identity = AirdressIdentity {
            airdress: airdress.to_owned(),
            root_public_key: *root_public_key,
            delegation,
        };
        let credential = BasicCredential::new(identity.to_identity_bytes()?).into_credential();
        let signing_identity = SigningIdentity::new(credential, sig_pub);

        let sealed = SealedStore::open(state_dir, state_key).map_err(|e| e.to_string())?;
        let group_store =
            SealedGroupStore::with_max_epoch_retention(sealed.clone(), max_epoch_retention);
        let key_package_store = SealedKeyPackageStore(sealed);

        let identity_provider = AirdressIdentityProvider::new();
        let client = Client::builder()
            .key_package_repo(key_package_store.clone())
            .group_state_storage(group_store.clone())
            .mls_rules(DefaultMlsRules::default())
            .crypto_provider(RustCryptoProvider::default())
            .identity_provider(identity_provider.clone())
            .signing_identity(signing_identity, secret_key, CIPHER_SUITE)
            .build();

        let engine = Self {
            client,
            public_key,
            identity_provider,
            key_packages: key_package_store,
            groups: group_store,
        };

        // First init on this state dir: establish the pool. The
        // publishable public messages persist alongside the private
        // halves, so the host can publish (or re-publish) them at any
        // point after this call — including after a restart.
        if engine.key_package_pool_count()? == 0 {
            engine.generate_key_packages(INITIAL_KEY_PACKAGE_POOL)?;
        }

        Ok(engine)
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Register the host's root-key cache and enter strict credential
    /// verification (one-way — this is the cutover switch). From here
    /// every accepted leaf must carry a v1 identity whose root key
    /// matches what the peer's operator publishes.
    pub fn set_root_key_lookup(&self, lookup: std::sync::Arc<dyn RootKeyLookup>) {
        self.identity_provider.set_root_key_lookup(lookup);
    }

    pub fn generate_key_package(&self) -> Result<Vec<u8>, String> {
        let mut generated = self.generate_key_packages(1)?;
        generated
            .pop()
            .ok_or_else(|| "no key package generated".to_owned())
    }

    /// Generate `count` fresh KeyPackages. The private halves land in
    /// the sealed store (written by mls-rs through the repo); the
    /// publishable public messages are persisted alongside them and
    /// returned for the host to publish. KeyPackages are single-use
    /// (RFC 9420 §12.4): consumption deletes both halves.
    pub fn generate_key_packages(&self, count: usize) -> Result<Vec<Vec<u8>>, String> {
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let before: std::collections::HashSet<Vec<u8>> = self
                .key_packages
                .pool_ids()
                .map_err(|e| e.to_string())?
                .into_iter()
                .collect();
            let kp = self
                .client
                .generate_key_package_message(
                    ExtensionList::default(),
                    ExtensionList::default(),
                    None,
                )
                .map_err(|e| format!("key package: {e}"))?;
            let bytes = kp.to_bytes().map_err(|e| format!("serialize: {e}"))?;

            // mls-rs inserted exactly one private half; find its id so
            // the public message can be persisted under the same name.
            let after = self.key_packages.pool_ids().map_err(|e| e.to_string())?;
            let new_id = after
                .into_iter()
                .find(|id| !before.contains(id))
                .ok_or("generated key package was not persisted")?;
            self.key_packages
                .insert_public(&new_id, &bytes)
                .map_err(|e| e.to_string())?;
            out.push(bytes);
        }
        Ok(out)
    }

    /// Number of unconsumed KeyPackage private halves in the pool.
    pub fn key_package_pool_count(&self) -> Result<usize, String> {
        self.key_packages.pool_count().map_err(|e| e.to_string())
    }

    /// The publishable public messages of every unconsumed KeyPackage
    /// — what the host publishes (or re-publishes after a restart).
    pub fn stored_key_packages(&self) -> Result<Vec<Vec<u8>>, String> {
        self.key_packages
            .stored_public_messages()
            .map_err(|e| e.to_string())
    }

    pub fn start_group(
        &mut self,
        peer_key_package: &[u8],
        first_message: &[u8],
    ) -> Result<StartGroupOutcome, String> {
        let peer_kp =
            MlsMessage::from_bytes(peer_key_package).map_err(|e| format!("bad kp: {e}"))?;

        let mut group = self
            .client
            .create_group(ExtensionList::default(), ExtensionList::default(), None)
            .map_err(|e| format!("create group: {e}"))?;

        let commit = group
            .commit_builder()
            .add_member(peer_kp)
            .map_err(|e| format!("add member: {e}"))?
            .build()
            .map_err(|e| format!("commit: {e}"))?;

        group
            .apply_pending_commit()
            .map_err(|e| format!("apply: {e}"))?;

        let welcome = commit
            .welcome_messages
            .into_iter()
            .next()
            .ok_or("no welcome")?
            .to_bytes()
            .map_err(|e| format!("welcome serialize: {e}"))?;

        let app = group
            .encrypt_application_message(first_message, Vec::new())
            .map_err(|e| format!("encrypt: {e}"))?
            .to_bytes()
            .map_err(|e| format!("app serialize: {e}"))?;

        let group_id = group.group_id().to_vec();
        group
            .write_to_storage()
            .map_err(|e| format!("persist group: {e}"))?;

        Ok(StartGroupOutcome {
            group_id,
            welcome,
            first_application: app,
        })
    }

    pub fn process_welcome(&mut self, welcome_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let msg = MlsMessage::from_bytes(welcome_bytes).map_err(|e| format!("bad welcome: {e}"))?;
        let (mut group, _) = self
            .client
            .join_group(None, &msg, None)
            .map_err(|e| format!("join: {e}"))?;
        let group_id = group.group_id().to_vec();
        group
            .write_to_storage()
            .map_err(|e| format!("persist group: {e}"))?;
        Ok(group_id)
    }

    /// Load a group from sealed storage. An unknown group and a
    /// group whose state file fails to unseal are both refusals — the
    /// latter must never fall back to a fresh group.
    fn load_group(&self, group_id: &[u8]) -> Result<Group<MlsConfig>, String> {
        self.client
            .load_group(group_id)
            .map_err(|e| format!("load group: {e}"))
    }

    pub fn encrypt(&mut self, group_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let mut group = self.load_group(group_id)?;
        let msg = group
            .encrypt_application_message(plaintext, Vec::new())
            .map_err(|e| format!("encrypt: {e}"))?;
        group
            .write_to_storage()
            .map_err(|e| format!("persist group: {e}"))?;
        msg.to_bytes().map_err(|e| format!("serialize: {e}"))
    }

    /// The sealed group store this engine writes through. Callers use
    /// it to inspect what the retention bound left behind.
    #[must_use]
    pub const fn group_store(&self) -> &SealedGroupStore {
        &self.groups
    }

    /// The current epoch of a stored group, or `None` if the group is
    /// not on disk.
    pub fn group_epoch(&self, group_id: &[u8]) -> Option<u64> {
        self.load_group(group_id).ok().map(|g| g.current_epoch())
    }

    /// Classify a processing failure: was the message's epoch trimmed
    /// out of the store by the retention bound, or is it just bad?
    ///
    /// Returns `Some` only when the epoch is strictly *behind* the
    /// group and older than the oldest record we still hold. An epoch
    /// in the future is a different condition (the device is behind on
    /// commits, not the message on keys) and must not be reported as
    /// `EpochUnavailable` — SPEC-061 FR-22 says so explicitly.
    fn epoch_unavailable(
        &self,
        group_id: &[u8],
        message_epoch: Option<u64>,
        current_epoch: u64,
    ) -> Option<EngineError> {
        let requested = message_epoch?;
        if requested >= current_epoch {
            return None;
        }
        let oldest_retained = self.groups.oldest_retained_epoch(group_id).ok()?;
        match oldest_retained {
            Some(oldest) if requested >= oldest => None,
            _ => Some(EngineError::EpochUnavailable {
                requested,
                oldest_retained,
            }),
        }
    }

    /// Decrypt an inbound application message.
    ///
    /// ## Persist after matching, never before (SPEC-061 FR-24 / D-9)
    ///
    /// `write_to_storage()` used to run between
    /// `process_incoming_message` and the kind match. A Commit
    /// delivered on this path is *applied* by mls-rs — the in-memory
    /// group advances an epoch — and the old ordering then sealed that
    /// advanced state to disk before telling the caller "not an
    /// application message". The caller believed nothing had happened
    /// while the on-disk group had silently moved to an epoch nobody
    /// chose, and every subsequent message failed against it.
    ///
    /// So: match first, and persist only inside the arm that accepted
    /// the message. The rejection arm persists nothing, and the
    /// mutated `group` is a local that is dropped here — the next call
    /// reloads the last state that was actually accepted.
    pub fn decrypt(
        &mut self,
        group_id: &[u8],
        message_bytes: &[u8],
    ) -> Result<Vec<u8>, EngineError> {
        let msg = MlsMessage::from_bytes(message_bytes)
            .map_err(|e| EngineError::Other(format!("bad message: {e}")))?;
        let message_epoch = msg.epoch();
        let mut group = self.load_group(group_id)?;
        let current_epoch = group.current_epoch();
        let received = match group.process_incoming_message(msg) {
            Ok(received) => received,
            Err(e) => {
                if let Some(trimmed) =
                    self.epoch_unavailable(group_id, message_epoch, current_epoch)
                {
                    return Err(trimmed);
                }
                return Err(EngineError::Other(format!("process: {e}")));
            }
        };
        match received {
            mls_rs::group::ReceivedMessage::ApplicationMessage(app) => {
                let plaintext = app.data().to_vec();
                // The accepting arm, and the only one that persists:
                // decryption ratchets the secret tree forward and that
                // has to survive a restart.
                group
                    .write_to_storage()
                    .map_err(|e| EngineError::Other(format!("persist group: {e}")))?;
                Ok(plaintext)
            }
            // Rejection arm. Persists nothing and drops the group, so a
            // Commit misrouted onto this path cannot advance the epoch
            // on disk behind the caller's back.
            _ => Err(EngineError::Other("not an application message".to_owned())),
        }
    }

    /// Build a commit for `group_id` and return its wire bytes without
    /// applying or persisting anything.
    ///
    /// Test-only scaffolding for SPEC-061 Phase 1: the real proposal
    /// and commit surface lands in Phase 4 (tasks 4.1-4.4). It exists
    /// here so a test can misroute a genuine Commit onto the
    /// application path and assert the on-disk epoch does not move.
    #[cfg(test)]
    pub(crate) fn test_only_commit_bytes(
        &mut self,
        group_id: &[u8],
    ) -> Result<Vec<u8>, EngineError> {
        let mut group = self.load_group(group_id)?;
        let output = group
            .commit(Vec::new())
            .map_err(|e| EngineError::Other(format!("commit: {e}")))?;
        output
            .commit_message
            .to_bytes()
            .map_err(|e| EngineError::Other(format!("commit serialize: {e}")))
    }

    /// Apply a self-commit to `group_id`, advancing and persisting the
    /// epoch. Test-only, for the same reason as
    /// [`MlsEngine::test_only_commit_bytes`].
    #[cfg(test)]
    pub(crate) fn test_only_advance_epoch(
        &mut self,
        group_id: &[u8],
    ) -> Result<Vec<u8>, EngineError> {
        let mut group = self.load_group(group_id)?;
        let output = group
            .commit(Vec::new())
            .map_err(|e| EngineError::Other(format!("commit: {e}")))?;
        group
            .apply_pending_commit()
            .map_err(|e| EngineError::Other(format!("apply: {e}")))?;
        group
            .write_to_storage()
            .map_err(|e| EngineError::Other(format!("persist group: {e}")))?;
        output
            .commit_message
            .to_bytes()
            .map_err(|e| EngineError::Other(format!("commit serialize: {e}")))
    }

    /// Process a commit produced by another member, advancing and
    /// persisting this engine's epoch. Test-only; Phase 4 task 4.1
    /// ships the real `process_commit`.
    #[cfg(test)]
    pub(crate) fn test_only_process_commit(
        &mut self,
        group_id: &[u8],
        message_bytes: &[u8],
    ) -> Result<(), EngineError> {
        let msg = MlsMessage::from_bytes(message_bytes)
            .map_err(|e| EngineError::Other(format!("bad message: {e}")))?;
        let mut group = self.load_group(group_id)?;
        match group
            .process_incoming_message(msg)
            .map_err(|e| EngineError::Other(format!("process: {e}")))?
        {
            mls_rs::group::ReceivedMessage::Commit(_) => {
                group
                    .write_to_storage()
                    .map_err(|e| EngineError::Other(format!("persist group: {e}")))?;
                Ok(())
            }
            _ => Err(EngineError::Other("not a commit".to_owned())),
        }
    }
}
