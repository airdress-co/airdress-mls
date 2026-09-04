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
use crate::storage::{SealedGroupStore, SealedKeyPackageStore, SealedStore};

const CIPHER_SUITE: CipherSuite = CipherSuite::CURVE25519_CHACHA;

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
        let group_store = SealedGroupStore(sealed.clone());
        let key_package_store = SealedKeyPackageStore(sealed);

        let identity_provider = AirdressIdentityProvider::new();
        let client = Client::builder()
            .key_package_repo(key_package_store.clone())
            .group_state_storage(group_store)
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

    pub fn decrypt(&mut self, group_id: &[u8], message_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let msg = MlsMessage::from_bytes(message_bytes).map_err(|e| format!("bad message: {e}"))?;
        let mut group = self.load_group(group_id)?;
        let received = group
            .process_incoming_message(msg)
            .map_err(|e| format!("process: {e}"))?;
        group
            .write_to_storage()
            .map_err(|e| format!("persist group: {e}"))?;
        match received {
            mls_rs::group::ReceivedMessage::ApplicationMessage(app) => Ok(app.data().to_vec()),
            _ => Err("not an application message".into()),
        }
    }
}
