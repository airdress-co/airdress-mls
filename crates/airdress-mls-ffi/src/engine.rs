//! Pure-Rust MLS engine — no FFI types, fully testable.

use std::collections::HashMap;

use chacha20poly1305::aead::OsRng;
use chacha20poly1305::aead::rand_core::RngCore;
use ed25519_dalek::SigningKey;
use mls_rs::client_builder::{
    BaseInMemoryConfig, WithCryptoProvider, WithIdentityProvider, WithMlsRules,
};
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::mls_rules::DefaultMlsRules;
use mls_rs::{CipherSuite, Client, ExtensionList, Group, MlsMessage};
use mls_rs_core::crypto::{SignaturePublicKey, SignatureSecretKey};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

const CIPHER_SUITE: CipherSuite = CipherSuite::CURVE25519_CHACHA;

type MlsConfig = WithIdentityProvider<
    BasicIdentityProvider,
    WithCryptoProvider<RustCryptoProvider, WithMlsRules<DefaultMlsRules, BaseInMemoryConfig>>,
>;

pub struct StartGroupOutcome {
    pub group_id: Vec<u8>,
    pub welcome: Vec<u8>,
    pub first_application: Vec<u8>,
}

pub struct MlsEngine {
    client: Client<MlsConfig>,
    groups: HashMap<Vec<u8>, Group<MlsConfig>>,
    public_key: Vec<u8>,
}

impl MlsEngine {
    pub fn new(airdress: &str) -> Result<Self, String> {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self::from_seed(airdress, &seed)
    }

    pub fn from_seed(airdress: &str, seed: &[u8; 32]) -> Result<Self, String> {
        let signing_key = SigningKey::from_bytes(seed);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();

        let secret_key = SignatureSecretKey::from(signing_key.to_keypair_bytes().to_vec());
        let sig_pub = SignaturePublicKey::from(signing_key.verifying_key().to_bytes().to_vec());

        let credential = BasicCredential::new(airdress.as_bytes().to_vec()).into_credential();
        let signing_identity = SigningIdentity::new(credential, sig_pub);

        let client = Client::builder()
            .mls_rules(DefaultMlsRules::default())
            .crypto_provider(RustCryptoProvider::default())
            .identity_provider(BasicIdentityProvider::new())
            .signing_identity(signing_identity, secret_key, CIPHER_SUITE)
            .build();

        Ok(Self {
            client,
            groups: HashMap::new(),
            public_key,
        })
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn generate_key_package(&self) -> Result<Vec<u8>, String> {
        let kp = self
            .client
            .generate_key_package_message(ExtensionList::default(), ExtensionList::default(), None)
            .map_err(|e| format!("key package: {e}"))?;
        kp.to_bytes().map_err(|e| format!("serialize: {e}"))
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
        self.groups.insert(group_id.clone(), group);

        Ok(StartGroupOutcome {
            group_id,
            welcome,
            first_application: app,
        })
    }

    pub fn process_welcome(&mut self, welcome_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let msg = MlsMessage::from_bytes(welcome_bytes).map_err(|e| format!("bad welcome: {e}"))?;
        let (group, _) = self
            .client
            .join_group(None, &msg, None)
            .map_err(|e| format!("join: {e}"))?;
        let group_id = group.group_id().to_vec();
        self.groups.insert(group_id.clone(), group);
        Ok(group_id)
    }

    pub fn encrypt(&mut self, group_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let group = self.groups.get_mut(group_id).ok_or("unknown group")?;
        let msg = group
            .encrypt_application_message(plaintext, Vec::new())
            .map_err(|e| format!("encrypt: {e}"))?;
        msg.to_bytes().map_err(|e| format!("serialize: {e}"))
    }

    pub fn decrypt(&mut self, group_id: &[u8], message_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let msg = MlsMessage::from_bytes(message_bytes).map_err(|e| format!("bad message: {e}"))?;
        let group = self.groups.get_mut(group_id).ok_or("unknown group")?;
        let received = group
            .process_incoming_message(msg)
            .map_err(|e| format!("process: {e}"))?;
        match received {
            mls_rs::group::ReceivedMessage::ApplicationMessage(app) => Ok(app.data().to_vec()),
            _ => Err("not an application message".into()),
        }
    }
}
