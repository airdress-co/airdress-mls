//! Pure-Rust MLS engine — no FFI types, fully testable.

use ed25519_dalek::SigningKey;
use mls_rs::client_builder::{
    BaseInMemoryConfig, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider,
    WithKeyPackageRepo, WithMlsRules,
};
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::BasicCredential;
use mls_rs::{CipherSuite, Client, ExtensionList, Group, MlsMessage};
use mls_rs_core::crypto::{SignaturePublicKey, SignatureSecretKey};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

use crate::binding::aad_for;
use crate::credential::{
    AirdressIdentity, AirdressIdentityProvider, Clock, RevocationLookup, RootKeyLookup, airdress_of,
};
use crate::rules::AirdressMlsRules;
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
        /// The epoch the message was sent in.
        requested: u64,
        /// The oldest epoch this device still holds, if it holds any.
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

impl EngineError {
    /// The stable code for this error — what a caller branches on.
    /// `Display` is the sentence for a journal and may be reworded;
    /// the code may not (rust guide R-ERR-6).
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::EpochUnavailable { .. } => ErrorCode::EpochUnavailable,
            Self::Other(_) => ErrorCode::Engine,
        }
    }
}

/// Stable error codes: what failed, as a number a client can branch
/// on without reading the message (rust guide R-ERR-6, R-ERR-7).
///
/// The values cross the C ABI (`airdress_mls_error_code`) and are a
/// promise to apps in the field: a value is never reused or renumbered,
/// and a new condition is a new value. Each says what the caller can do
/// about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ErrorCode {
    /// The engine refused or failed, for a reason with no code of its
    /// own (a bad credential, a corrupt message, a storage failure).
    /// Not retryable as is; the message says why.
    Engine = 1,
    /// An argument was null, the wrong length or not UTF-8. A bug in
    /// the caller; retrying the same call fails the same way.
    InvalidArgument = 2,
    /// The engine handle names no live engine: it was destroyed, or
    /// never created. Create a new engine.
    InvalidHandle = 3,
    /// A panic inside the library was caught. A bug in this library or
    /// in mls-rs; the engine stays usable, and the input that caused it
    /// should be dropped rather than retried.
    Internal = 4,
    /// The message is from an epoch this device has deliberately
    /// trimmed from its sealed state ([`EngineError::EpochUnavailable`]).
    /// Not corrupt and not retryable: catch up from the current epoch
    /// (or rejoin), and drop the message.
    EpochUnavailable = 5,
    /// An unbound send or establishment past the v2 credential cutover.
    /// Call the `_bound` form with the sender's airdress.
    BindingRequired = 6,
}

impl ErrorCode {
    /// The number that crosses the C ABI.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

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

/// The MLS group id a message carries in its framing, in the clear.
///
/// RFC 9420 puts `group_id` in `PrivateMessage` and `PublicMessage`
/// outside the encryption, so this needs no key and no engine: a
/// receiver files a message by the group it names, which MLS then
/// authenticates on decrypt. A Welcome carries none (the group's
/// identity is inside the encrypted `GroupInfo`) and is an error, as is
/// anything that does not parse.
pub fn message_group_id(message: &[u8]) -> Result<Vec<u8>, String> {
    let msg = MlsMessage::from_bytes(message).map_err(|e| format!("bad message: {e}"))?;
    msg.group_id()
        .map(<[u8]>::to_vec)
        .ok_or_else(|| "this message carries no group id in its framing".to_owned())
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
            AirdressMlsRules,
            WithGroupStateStorage<
                SealedGroupStore,
                WithKeyPackageRepo<SealedKeyPackageStore, BaseInMemoryConfig>,
            >,
        >,
    >,
>;

/// What establishing a group produced, to be put on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartGroupOutcome {
    /// The new group's id.
    pub group_id: Vec<u8>,
    /// The Welcome for the added member; empty for a solo group.
    pub welcome: Vec<u8>,
    /// The first application message, bound to the group and sender.
    pub first_application: Vec<u8>,
}

/// What a commit did to the membership, and what has to go on the
/// wire because of it (SPEC-061 FR-4).
///
/// `added` / `removed` / `members` all carry **member identities** —
/// `airdress ‖ 0x1F ‖ device_id` under the v2 credential, the bare
/// airdress under v1 — because that is the value `mls-rs` uses to tell
/// leaves apart and therefore the only value that names a device
/// unambiguously.
///
/// The delta is reported rather than left implicit so that:
///
/// - the caller can render "Alice removed her old phone" without
///   re-deriving it from two roster snapshots, and
/// - **a removed device learns that it was removed.** `self_removed`
///   is the signal that turns a silent, permanent decryption failure
///   into a state the client can act on. Without it the removed device
///   sees only that nothing decrypts any more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitOutcome {
    /// The commit message to publish. Empty when this outcome
    /// describes an inbound commit that was processed rather than one
    /// that was built.
    pub commit: Vec<u8>,
    /// The Welcome for members added by this commit, if any.
    pub welcome: Option<Vec<u8>>,
    /// The epoch the group is at after applying the commit.
    pub epoch: u64,
    /// Member identities that joined.
    pub added: Vec<Vec<u8>>,
    /// Member identities that left.
    pub removed: Vec<Vec<u8>>,
    /// Whether **this** device was the one removed. When true the
    /// group is gone: nothing sent after this commit is readable here,
    /// and the only way back in is a rejoin (SPEC-061 FR-30).
    pub self_removed: bool,
    /// The full membership after the commit.
    pub members: Vec<Vec<u8>>,
}

/// One leaf of a group, as the caller sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMember {
    /// Leaf index. Stable for the life of the leaf; this is what a
    /// `Remove` names.
    pub index: u32,
    /// `airdress ‖ 0x1F ‖ device_id` (v2) or the bare airdress (v1).
    pub identity: Vec<u8>,
    /// The airdress this leaf belongs to — what SPEC-061 FR-25 turns
    /// on.
    pub airdress: String,
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

/// One device's MLS client: its signing identity, its sealed state and
/// the credential rules it enforces.
pub struct MlsEngine {
    client: Client<MlsConfig>,
    public_key: Vec<u8>,
    identity_provider: AirdressIdentityProvider,
    key_packages: SealedKeyPackageStore,
    /// A second handle on the same sealed group store `mls-rs` writes
    /// through, so the engine can ask which epochs survived the
    /// retention trim (SPEC-061 FR-22) without decoding the record.
    groups: SealedGroupStore,
    /// Groups carrying a commit that has been applied in memory and
    /// deliberately NOT persisted, awaiting
    /// [`MlsEngine::confirm_commit`] or [`MlsEngine::abort_commit`]
    /// (SPEC-061 FR-7). See the two-phase note on
    /// [`MlsEngine::commit_pending`].
    pending: std::collections::HashMap<Vec<u8>, Group<MlsConfig>>,
    /// Proposals staged for this group's next commit, held **by
    /// value** so the commit is the only thing that has to reach the
    /// group (design §6.1: one `mls_commit` envelope, no proposal
    /// envelope kind exists).
    ///
    /// A by-reference proposal would have to be published and
    /// processed by every member before any commit referencing it
    /// could be applied — otherwise they fail with "by-ref proposal
    /// not found". Inbound bare proposals from other members are still
    /// held by reference, through
    /// [`MlsEngine::process_proposal`](Self::process_proposal); this
    /// map is only for proposals this device originates.
    staged: std::collections::HashMap<Vec<u8>, Vec<StagedProposal>>,
}

/// A proposal this device originated, waiting to be folded into its
/// next commit by value.
#[derive(Debug, Clone, PartialEq, Eq)]
enum StagedProposal {
    /// Serialized `KeyPackage` of the member to add.
    Add(Vec<u8>),
    /// Leaf index of the member to remove.
    Remove(u32),
}

impl core::fmt::Debug for MlsEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The client holds the signing key, so only the public half shows.
        f.debug_struct("MlsEngine")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
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
        // The version follows the delegation the host handed us: one
        // carrying `device_id` + `expires_at` is v2 (SPEC-061 FR-15),
        // anything else is v1. Whoever signs the delegation decides
        // the version by deciding what to put in it, which is why no
        // version argument crosses the FFI.
        let identity =
            AirdressIdentity::from_delegation(airdress.to_owned(), *root_public_key, delegation);
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
            // The rules read the revocation witness from the same
            // provider that runs check 5, so a host registers one
            // lookup and both answer from it.
            .mls_rules(AirdressMlsRules::sharing_revocation_with(
                &identity_provider,
            ))
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
            pending: std::collections::HashMap::new(),
            staged: std::collections::HashMap::new(),
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

    /// The device's session public key, which signs its leaf.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Register the host's root-key cache and enter strict credential
    /// verification (one-way). From here every accepted leaf must
    /// carry a structured identity whose root key matches what the
    /// peer's operator publishes.
    pub fn set_root_key_lookup(&self, lookup: std::sync::Arc<dyn RootKeyLookup>) {
        self.identity_provider.set_root_key_lookup(lookup);
    }

    /// Register the host's device-revocation state (SPEC-061 FR-19,
    /// check 5). The host answers from the enrollment revocation
    /// state it already maintains; this crate fetches nothing.
    pub fn set_revocation_lookup(&self, revocation: std::sync::Arc<dyn RevocationLookup>) {
        self.identity_provider.set_revocation_lookup(revocation);
    }

    /// Replace the wall clock used for delegation expiry when
    /// `mls-rs` supplies no timestamp (SPEC-061 FR-18). Production
    /// leaves this at the system clock.
    pub fn set_clock(&self, clock: std::sync::Arc<dyn Clock>) {
        self.identity_provider.set_clock(clock);
    }

    /// Enter the SPEC-061 v2 cutover (FR-20): `v: 1` identities stop
    /// being accepted. One-way, per NFR-15.
    pub fn set_v2_cutover(&self) {
        self.identity_provider.set_v2_cutover();
    }

    /// Whether the v2 cutover has been entered.
    #[must_use]
    pub fn is_v2_cutover(&self) -> bool {
        self.identity_provider.is_v2_cutover()
    }

    /// One fresh KeyPackage, persisted to the pool like
    /// [`Self::generate_key_packages`].
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

    /// Create a group with one peer and send the first message.
    ///
    /// `from_airdress` is the sender component of the SPEC-061 FR-17a
    /// AAD binding; see [`MlsEngine::encrypt`]. The group component is
    /// the group this call is about to create, so — unlike D-8's
    /// version — there is nothing here that can fail to be computable
    /// and nothing to resolve before `create_group`.
    pub fn start_group(
        &mut self,
        peer_key_package: &[u8],
        first_message: &[u8],
        from_airdress: &str,
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

        let group_id = group.group_id().to_vec();
        let aad = aad_for(
            self.identity_provider.is_v2_cutover(),
            &group_id,
            from_airdress,
        );
        let app = group
            .encrypt_application_message(first_message, aad)
            .map_err(|e| format!("encrypt: {e}"))?
            .to_bytes()
            .map_err(|e| format!("app serialize: {e}"))?;

        group
            .write_to_storage()
            .map_err(|e| format!("persist group: {e}"))?;

        Ok(StartGroupOutcome {
            group_id,
            welcome,
            first_application: app,
        })
    }

    /// Create a group with **no other member** and encrypt the first
    /// message into it.
    ///
    /// ## Why this exists (SPEC-061 task 7.2)
    ///
    /// The owner's self thread is an ordinary conversation whose
    /// members are the owner's own devices (design §5.5). An owner
    /// with one device therefore has a conversation with one member,
    /// and [`Self::start_group`] cannot express it: it demands a peer
    /// `KeyPackage`, and the only one a lone device holds is its own —
    /// which under the task 3.3 identity (`airdress ‖ 0x1F ‖
    /// device_id`) is the *same* member, so `mls-rs` refuses the Add
    /// with "duplicate signature key, hpke key or identity found at
    /// index 0".
    ///
    /// Before SPEC-061 that case never arose: the `self.local`
    /// companion credential always supplied a second leaf, which is
    /// precisely the workaround task 7.2 retires. Retiring it without
    /// this would have left every single-device owner — the common
    /// case — with no self thread at all, so the removal table's
    /// "ordinary conversation" is only true once a conversation may
    /// have one member.
    ///
    /// There is no Welcome, because nobody is added; the outcome's
    /// `welcome` is empty and callers must not put it on the wire. A
    /// second device joins later through an ordinary `Add` commit
    /// ([`Self::propose_add`]), which does produce one — the solo group
    /// is a starting point, not a separate kind of group.
    ///
    /// The AAD binds the group this call creates and `from_airdress`
    /// (FR-17a, design D-10).
    ///
    /// # Errors
    ///
    /// Group creation, encryption or persistence failures.
    pub fn start_group_solo(
        &mut self,
        first_message: &[u8],
        from_airdress: &str,
    ) -> Result<StartGroupOutcome, String> {
        let mut group = self
            .client
            .create_group(ExtensionList::default(), ExtensionList::default(), None)
            .map_err(|e| format!("create group: {e}"))?;

        let group_id = group.group_id().to_vec();
        let aad = aad_for(
            self.identity_provider.is_v2_cutover(),
            &group_id,
            from_airdress,
        );
        let app = group
            .encrypt_application_message(first_message, aad)
            .map_err(|e| format!("encrypt: {e}"))?
            .to_bytes()
            .map_err(|e| format!("app serialize: {e}"))?;

        group
            .write_to_storage()
            .map_err(|e| format!("persist group: {e}"))?;

        Ok(StartGroupOutcome {
            group_id,
            welcome: Vec::new(),
            first_application: app,
        })
    }

    /// Join the group a Welcome invites this device into. Returns the
    /// group id.
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

    /// Encrypt an application message under a group's current epoch.
    ///
    /// ## The binding (SPEC-061 FR-17a / design D-10)
    ///
    /// Past the v2 cutover the message's AAD is the group id plus
    /// `from_airdress`, so a ciphertext re-attributed to another
    /// sender fails to decrypt instead of rendering under the wrong
    /// heading with a valid signature, and a ciphertext moved to
    /// another conversation is filed by the group it decrypted under
    /// rather than by whatever the operator asserted. Before the
    /// cutover the AAD stays empty, because a `v: 1` peer computes an
    /// empty AAD and the two must agree byte for byte.
    ///
    /// The group id is read off the framing in the clear (RFC 9420),
    /// so the receiver can compute the same value **before** it
    /// decrypts — the constraint that shaped D-8 and shapes this.
    /// Unlike D-8's conversation id it is also the *same* value on
    /// both sides no matter which owner, principal or operator each
    /// member sits behind (design D-10).
    pub fn encrypt(
        &mut self,
        group_id: &[u8],
        plaintext: &[u8],
        from_airdress: &str,
    ) -> Result<Vec<u8>, String> {
        let mut group = self.load_group(group_id)?;
        let aad = aad_for(
            self.identity_provider.is_v2_cutover(),
            group.group_id(),
            from_airdress,
        );
        let msg = group
            .encrypt_application_message(plaintext, aad)
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
        from_airdress: &str,
    ) -> Result<Vec<u8>, EngineError> {
        let msg = MlsMessage::from_bytes(message_bytes)
            .map_err(|e| EngineError::Other(format!("bad message: {e}")))?;
        let message_epoch = msg.epoch();
        let mut group = self.load_group(group_id)?;
        // The group actually loaded is the group component of the
        // expected AAD — never a value the caller or the operator
        // asserted. mls-rs refuses a message framed for a different
        // group, so by the time the comparison runs the two agree.
        let expected_aad = aad_for(
            self.identity_provider.is_v2_cutover(),
            group.group_id(),
            from_airdress,
        );
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
                // The AAD is authenticated by the AEAD, but mls-rs
                // hands it back rather than checking it against an
                // expectation — it has no way to know ours. Compare
                // here, and reject before the plaintext is handed on:
                // a ciphertext re-attributed to another sender must
                // fail, not render under the wrong heading (FR-17a /
                // AC-11).
                if app.authenticated_data != expected_aad {
                    return Err(EngineError::Other(
                        "this message does not belong to this group or sender".to_owned(),
                    ));
                }
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

    // -----------------------------------------------------------------
    // SPEC-061 Phase 4: proposals and commits
    //
    // Everything below replaces the Phase 1 `test_only_*` scaffolding
    // (`test_only_commit_bytes`, `test_only_advance_epoch`,
    // `test_only_process_commit`), which existed only so a Phase 1
    // test could misroute a genuine Commit onto the application path.
    // The regression tests that used it now drive the real surface.
    // -----------------------------------------------------------------

    /// Every leaf of a group, in leaf-index order.
    ///
    /// # Errors
    ///
    /// The group is not on disk, or a leaf carries an unreadable
    /// credential.
    pub fn group_members(&self, group_id: &[u8]) -> Result<Vec<GroupMember>, String> {
        let group = self.load_group(group_id)?;
        self.roster_of(&group)
    }

    fn roster_of(&self, group: &Group<MlsConfig>) -> Result<Vec<GroupMember>, String> {
        group
            .roster()
            .members_iter()
            .map(|m| {
                Ok(GroupMember {
                    index: m.index,
                    identity: self.member_identity_bytes(m.signing_identity())?,
                    airdress: airdress_of(m.signing_identity()).map_err(|e| e.to_string())?,
                })
            })
            .collect()
    }

    /// The bytes `mls-rs` uses to tell one leaf from another —
    /// `airdress ‖ 0x1F ‖ device_id` under v2. Resolved through this
    /// engine's own identity provider, so the value matches what the
    /// tree used and does not drift with the cutover flag.
    fn member_identity_bytes(&self, signing_identity: &SigningIdentity) -> Result<Vec<u8>, String> {
        use mls_rs::IdentityProvider as _;
        self.identity_provider
            .identity(signing_identity, &ExtensionList::default())
            .map_err(|e| e.to_string())
    }

    /// This device's own leaf index in a group.
    fn own_index(group: &Group<MlsConfig>) -> u32 {
        group.current_member_index()
    }

    /// Stage an `Add` for this group's next commit (SPEC-061 FR-3).
    ///
    /// Staged **by value**: the commit built by
    /// [`MlsEngine::commit_pending`] carries the proposal itself, so
    /// the commit is the only message that has to reach the group.
    /// That matches design §6.1's flow — one `mls_commit` envelope —
    /// and it has to, because there is no proposal envelope kind for a
    /// by-reference proposal to travel in, and a member who never saw
    /// the reference cannot apply a commit that names it.
    ///
    /// # Errors
    ///
    /// The group is unknown or the bytes are not a KeyPackage.
    pub fn propose_add(&mut self, group_id: &[u8], key_package: &[u8]) -> Result<(), String> {
        MlsMessage::from_bytes(key_package).map_err(|e| format!("bad kp: {e}"))?;
        // Refuse now if the group is not ours, rather than at commit
        // time when the caller has forgotten why it staged this.
        self.load_group(group_id)?;
        self.staged
            .entry(group_id.to_vec())
            .or_default()
            .push(StagedProposal::Add(key_package.to_vec()));
        Ok(())
    }

    /// Stage a `Remove` of the leaf at `index` for this group's next
    /// commit (SPEC-061 FR-2). Staged by value, for the same reason as
    /// [`MlsEngine::propose_add`].
    ///
    /// ## A refused removal fails here first
    ///
    /// [`crate::rules::AirdressMlsRules`] is the enforcement point and
    /// catches a refused removal on both the send and the receive side,
    /// including a hand-crafted proposal from a client that has had
    /// this check patched out. The check repeated here is the early
    /// refusal SPEC-061 FR-25 asks for: it fails before the proposal
    /// exists, so the caller gets a comprehensible error rather than a
    /// commit that will not build. It is the rules' own function, with
    /// this engine's revocation lookup, so the two cannot disagree:
    ///
    /// - another airdress's leaf is refused (FR-25);
    /// - inside one airdress, once a `v: 3` leaf is on either side,
    ///   another person's leaf is refused unless it is a `v: 3` leaf
    ///   whose `device_id` the registered revocation lookup answers
    ///   `Revoked` for (SPEC-144 F-7, FR-53).
    ///
    /// # Errors
    ///
    /// The group is unknown, the index names no leaf, or the rules
    /// refuse the removal.
    pub fn propose_remove(&mut self, group_id: &[u8], index: u32) -> Result<(), String> {
        let group = self.load_group(group_id)?;
        self.refuse_unauthorised_removal(&group, index)?;
        drop(group);
        self.staged
            .entry(group_id.to_vec())
            .or_default()
            .push(StagedProposal::Remove(index));
        Ok(())
    }

    fn refuse_unauthorised_removal(
        &self,
        group: &Group<MlsConfig>,
        index: u32,
    ) -> Result<(), String> {
        let own = group
            .member_at_index(Self::own_index(group))
            .ok_or("this device has no leaf in the group")?;
        let target = group
            .member_at_index(index)
            .ok_or_else(|| format!("no member at leaf {index}"))?;
        let revocation = self.identity_provider.registered_revocation_lookup();
        crate::rules::check_removal(
            own.signing_identity(),
            target.signing_identity(),
            revocation.as_deref(),
        )
        .map_err(|e| e.to_string())
    }

    /// Propose replacing this device's own leaf key (SPEC-061 FR-1) —
    /// the post-compromise-security primitive.
    ///
    /// Returns the bare proposal for publication. This is the one
    /// operation that MUST travel by reference: RFC 9420 forbids a
    /// committer from including its own `Update`, so another member
    /// holds it (via [`MlsEngine::process_proposal`]) and commits it.
    ///
    /// A device healing itself without waiting for anyone calls
    /// [`MlsEngine::commit_pending`] instead: a commit carries a path
    /// update, which rotates this leaf's key with the same effect and
    /// needs nobody else's cooperation.
    ///
    /// # Errors
    ///
    /// The group is unknown, or `mls-rs` refuses the proposal.
    pub fn propose_update(&mut self, group_id: &[u8]) -> Result<Vec<u8>, String> {
        let mut group = self.load_group(group_id)?;
        let msg = group
            .propose_update(Vec::new())
            .map_err(|e| format!("propose update: {e}"))?;
        group
            .write_to_storage()
            .map_err(|e| format!("persist group: {e}"))?;
        msg.to_bytes().map_err(|e| format!("serialize: {e}"))
    }

    /// Hold an inbound bare proposal for the next commit (SPEC-061
    /// FR-5).
    ///
    /// `ReceivedMessage::Proposal` used to be an error on every path.
    ///
    /// # Errors
    ///
    /// The group is unknown, the bytes are not a proposal, or the
    /// proposal is refused by the MLS rules (a cross-airdress `Remove`,
    /// or another person's leaf without the revocation witness, is
    /// refused here — the rules' receive side).
    pub fn process_proposal(
        &mut self,
        group_id: &[u8],
        message_bytes: &[u8],
    ) -> Result<(), String> {
        let msg = MlsMessage::from_bytes(message_bytes).map_err(|e| format!("bad message: {e}"))?;
        let mut group = self.load_group(group_id)?;
        match group
            .process_incoming_message(msg)
            .map_err(|e| format!("process: {e}"))?
        {
            mls_rs::group::ReceivedMessage::Proposal(_) => {
                // A held proposal is group state: it has to survive a
                // restart or the commit that was meant to carry it
                // silently drops it.
                group
                    .write_to_storage()
                    .map_err(|e| format!("persist group: {e}"))
            }
            _ => Err("not a proposal".to_owned()),
        }
    }

    /// Commit every held proposal, advancing this device's epoch in
    /// memory and **deliberately not persisting** (SPEC-061 FR-7).
    ///
    /// ## Why this is two calls and not one
    ///
    /// `apply_pending_commit()` moves the group to a new epoch. If the
    /// device seals that state and then fails to publish the commit —
    /// no network, or a `409 epoch_conflict` because another device
    /// committed from the same epoch first — it has **forked the
    /// group**. Every other member is at the old epoch; this one is
    /// alone at a new one, and MLS has no way back. The fork is
    /// unrecoverable except by rejoin.
    ///
    /// So: not-persisted is the default state, and confirmation is the
    /// exception. The caller publishes the returned bytes, and only on
    /// a `202` calls [`MlsEngine::confirm_commit`]. On anything else it
    /// calls [`MlsEngine::abort_commit`], and the sealed state is
    /// still where it was.
    ///
    /// Calling this with no held proposals is not a no-op: the commit
    /// still carries a path update, which is exactly the self-heal
    /// FR-1 asks for.
    ///
    /// ## A commit that fails to build drops what was staged
    ///
    /// The staged proposals used to survive a failed build, because
    /// only [`MlsEngine::confirm_commit`] and
    /// [`MlsEngine::abort_commit`] cleared them — and `abort_commit`
    /// refuses to run when nothing is pending, which after a failed
    /// build is exactly the state. So one `Add` of a `KeyPackage` the
    /// rules refuse (a sibling whose delegation chains to a root this
    /// device does not hold) stayed staged for the life of the engine,
    /// and every later commit on that group — the next sibling pass,
    /// the post-compromise self-commit, the revocation sweep — failed
    /// on the same stale proposal. Measured on three phones on
    /// 2026-09-23 (SPEC-111 phase A). The caller re-proposes from a
    /// fresh read of the tree on its next pass, which is the same
    /// contract `abort_commit` already gives it.
    ///
    /// # Errors
    ///
    /// The group is unknown, a commit is already awaiting
    /// confirmation, or `mls-rs` refuses the commit.
    pub fn commit_pending(&mut self, group_id: &[u8]) -> Result<CommitOutcome, String> {
        if self.pending.contains_key(group_id) {
            return Err("a commit for this group is already awaiting confirmation".to_owned());
        }
        let staged = self.staged.remove(group_id).unwrap_or_default();
        let mut group = self.load_group(group_id)?;
        let before = self.identity_set(&group)?;
        let mut builder = group.commit_builder();
        for proposal in &staged {
            builder = match proposal {
                StagedProposal::Add(kp) => {
                    let kp = MlsMessage::from_bytes(kp).map_err(|e| format!("bad kp: {e}"))?;
                    builder
                        .add_member(kp)
                        .map_err(|e| format!("add member: {e}"))?
                }
                StagedProposal::Remove(index) => builder
                    .remove_member(*index)
                    .map_err(|e| format!("remove member: {e}"))?,
            };
        }
        let output = builder.build().map_err(|e| format!("commit: {e}"))?;
        group
            .apply_pending_commit()
            .map_err(|e| format!("apply: {e}"))?;
        let commit = output
            .commit_message
            .to_bytes()
            .map_err(|e| format!("commit serialize: {e}"))?;
        let welcome = output
            .welcome_messages
            .into_iter()
            .next()
            .map(|w| w.to_bytes().map_err(|e| format!("welcome serialize: {e}")))
            .transpose()?;
        let after = self.identity_set(&group)?;
        let outcome = CommitOutcome {
            commit,
            welcome,
            epoch: group.current_epoch(),
            added: after.difference_from(&before),
            removed: before.difference_from(&after),
            // The committer cannot have removed itself: `mls-rs`
            // refuses a self-Remove in one's own commit.
            self_removed: false,
            members: after.0,
        };
        self.pending.insert(group_id.to_vec(), group);
        Ok(outcome)
    }

    /// Persist a commit built by [`MlsEngine::commit_pending`], after
    /// the operator has accepted it.
    ///
    /// # Errors
    ///
    /// No commit is awaiting confirmation for this group, or the
    /// sealed store refuses the write.
    pub fn confirm_commit(&mut self, group_id: &[u8]) -> Result<u64, String> {
        let mut group = self
            .pending
            .remove(group_id)
            .ok_or("no commit is awaiting confirmation for this group")?;
        group
            .write_to_storage()
            .map_err(|e| format!("persist group: {e}"))?;
        self.staged.remove(group_id);
        Ok(group.current_epoch())
    }

    /// Discard a commit built by [`MlsEngine::commit_pending`].
    ///
    /// The in-memory mutation is dropped and the group reverts to
    /// whatever the sealed store holds — which is the pre-commit
    /// epoch, because `commit_pending` never wrote. This is a reload,
    /// not an undo: `mls-rs` has no undo, and a hand-rolled one would
    /// be wrong in a way that only surfaces under concurrency.
    ///
    /// # Errors
    ///
    /// No commit was awaiting confirmation for this group.
    pub fn abort_commit(&mut self, group_id: &[u8]) -> Result<u64, String> {
        self.pending
            .remove(group_id)
            .ok_or("no commit is awaiting confirmation for this group")?;
        // Staged proposals are dropped too. A retry after catch-up
        // re-proposes: leaf indices can have moved under the commit
        // that won, so replaying the old ones would remove the wrong
        // member (design §6.3).
        self.staged.remove(group_id);
        // Prove the reload works rather than asserting it: the caller
        // is about to use this group again.
        let group = self.load_group(group_id)?;
        Ok(group.current_epoch())
    }

    /// Apply another member's commit: advance the epoch, persist, and
    /// report the membership delta (SPEC-061 FR-4).
    ///
    /// `ReceivedMessage::Commit` used to be an error here, which is
    /// why neither member removal nor post-compromise security existed.
    ///
    /// Persistence follows the same rule as the application path
    /// (design D-9): it happens **inside the accepting arm**, and a
    /// message that turns out not to be a commit persists nothing.
    ///
    /// # Errors
    ///
    /// The group is unknown, the message is not a commit, its epoch
    /// has been trimmed ([`EngineError::EpochUnavailable`]), or
    /// `mls-rs` refuses it.
    pub fn process_commit(
        &mut self,
        group_id: &[u8],
        message_bytes: &[u8],
    ) -> Result<CommitOutcome, EngineError> {
        let msg = MlsMessage::from_bytes(message_bytes)
            .map_err(|e| EngineError::Other(format!("bad message: {e}")))?;
        let message_epoch = msg.epoch();
        let mut group = self.load_group(group_id)?;
        let current_epoch = group.current_epoch();
        let before = self.identity_set(&group).map_err(EngineError::Other)?;
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
        let mls_rs::group::ReceivedMessage::Commit(description) = received else {
            // Rejection arm: persists nothing and drops the group.
            return Err(EngineError::Other("not a commit".to_owned()));
        };
        let self_removed = matches!(
            description.effect,
            mls_rs::group::CommitEffect::Removed { .. }
        );
        let (after, epoch) = if self_removed {
            // A removed member's group object is spent — the roster it
            // could report is the one it was evicted from. Report the
            // eviction and nothing else.
            (IdentitySet(Vec::new()), current_epoch)
        } else {
            (
                self.identity_set(&group).map_err(EngineError::Other)?,
                group.current_epoch(),
            )
        };
        // The accepting arm, and the only one that persists. A removed
        // member persists too: the state that records "you are out" is
        // what stops the next start-up believing it is still a member.
        group
            .write_to_storage()
            .map_err(|e| EngineError::Other(format!("persist group: {e}")))?;
        Ok(CommitOutcome {
            commit: Vec::new(),
            welcome: None,
            epoch,
            added: after.difference_from(&before),
            removed: before.difference_from(&after),
            self_removed,
            members: after.0,
        })
    }

    fn identity_set(&self, group: &Group<MlsConfig>) -> Result<IdentitySet, String> {
        let mut out = Vec::new();
        for member in group.roster().members_iter() {
            out.push(self.member_identity_bytes(member.signing_identity())?);
        }
        out.sort_unstable();
        Ok(IdentitySet(out))
    }
}

/// Sorted member identities, for computing a membership delta by
/// difference rather than by decoding proposal internals — the delta
/// is then correct for any commit, including ones carrying proposals
/// this crate did not build.
struct IdentitySet(Vec<Vec<u8>>);

impl IdentitySet {
    fn difference_from(&self, other: &Self) -> Vec<Vec<u8>> {
        self.0
            .iter()
            .filter(|id| !other.0.contains(id))
            .cloned()
            .collect()
    }
}
