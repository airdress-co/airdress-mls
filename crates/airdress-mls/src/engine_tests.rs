//! The engine's key-package pool, through real engines past the cutover:
//!
//! - a pool from an engine that did not advertise the group extension
//!   types is replaced when the engine opens.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::{Client, ExtensionList};
use mls_rs_core::crypto::{SignaturePublicKey, SignatureSecretKey};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

use super::{CIPHER_SUITE, MlsEngine, leaf_advertises_group_extensions};
use crate::credential::{DeviceStatus, test_support::signed_delegation_json_v2};
use crate::storage::{SealedKeyPackageStore, SealedStore};

const ALICE: &str = "alice.test";
const BOB: &str = "bob.test";
const STATE_KEY: [u8; 32] = [7u8; 32];

fn root_of(airdress: &str) -> SigningKey {
    SigningKey::from_bytes(&[if airdress == ALICE { 111 } else { 112 }; 32])
}

fn device(airdress: &str, name: &str, seed: u8, dir: &tempfile::TempDir) -> MlsEngine {
    let root = root_of(airdress);
    let session = SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes();
    let engine = MlsEngine::from_seed(
        airdress,
        &[seed; 32],
        &root.verifying_key().to_bytes(),
        &signed_delegation_json_v2(&root, airdress, &session, name, "2099-01-01T00:00:00Z"),
        dir.path().to_str().unwrap(),
        &STATE_KEY,
    )
    .unwrap();
    engine.set_root_key_lookup(Arc::new(|a: &str| {
        [ALICE, BOB]
            .contains(&a)
            .then(|| root_of(a).verifying_key().to_bytes())
    }));
    engine.set_revocation_lookup(Arc::new(|_: &str| Some(DeviceStatus::Active)));
    engine.set_v2_cutover();
    engine
}

/// A key package made the way an engine made them before it advertised
/// the group extension types: the same store, no `extension_types`.
fn store_a_package_without_group_extensions(dir: &tempfile::TempDir) {
    let store =
        SealedKeyPackageStore(SealedStore::open(dir.path().to_str().unwrap(), &STATE_KEY).unwrap());
    let key = SigningKey::from_bytes(&[42; 32]);
    let identity = SigningIdentity::new(
        BasicCredential::new(b"older-engine".to_vec()).into_credential(),
        SignaturePublicKey::from(key.verifying_key().to_bytes().to_vec()),
    );
    let client = Client::builder()
        .key_package_repo(store.clone())
        .crypto_provider(RustCryptoProvider::default())
        .identity_provider(BasicIdentityProvider::new())
        .signing_identity(
            identity,
            SignatureSecretKey::from(key.to_keypair_bytes().to_vec()),
            CIPHER_SUITE,
        )
        .build();
    let before = store.pool_ids().unwrap();
    let message = client
        .generate_key_package_message(ExtensionList::default(), ExtensionList::default(), None)
        .unwrap();
    let id = store
        .pool_ids()
        .unwrap()
        .into_iter()
        .find(|id| !before.contains(id))
        .unwrap();
    store
        .insert_public(&id, &message.to_bytes().unwrap())
        .unwrap();
}

fn every_stored_package_advertises_the_group_extensions(engine: &MlsEngine) -> bool {
    use mls_rs::mls_rs_codec::MlsEncode as _;
    engine.stored_key_packages().unwrap().iter().all(|bytes| {
        let kp = mls_rs::MlsMessage::from_bytes(bytes)
            .unwrap()
            .into_key_package()
            .unwrap();
        leaf_advertises_group_extensions(&kp.mls_encode_to_vec().unwrap())
    })
}

#[test]
fn opening_replaces_key_packages_that_lack_the_group_extensions() {
    let dir = tempfile::tempdir().unwrap();
    let current = device(ALICE, "alice-phone", 1, &dir)
        .stored_key_packages()
        .unwrap();
    let store =
        SealedKeyPackageStore(SealedStore::open(dir.path().to_str().unwrap(), &STATE_KEY).unwrap());
    store_a_package_without_group_extensions(&dir);
    store_a_package_without_group_extensions(&dir);
    let old: Vec<_> = store
        .stored_public_messages()
        .unwrap()
        .into_iter()
        .filter(|p| !current.contains(p))
        .collect();
    assert_eq!(old.len(), 2);

    let engine = device(ALICE, "alice-phone", 1, &dir);
    let now = engine.stored_key_packages().unwrap();
    assert!(
        old.iter().all(|p| !now.contains(p)),
        "a package without the group extension types was kept"
    );
    assert!(current.iter().all(|p| now.contains(p)));
    assert_eq!(now.len(), current.len() + 2, "each one is replaced");
    assert_eq!(engine.key_package_pool_count().unwrap(), now.len());
    assert!(every_stored_package_advertises_the_group_extensions(
        &engine
    ));
}

#[test]
fn opening_keeps_key_packages_that_advertise_the_group_extensions() {
    let dir = tempfile::tempdir().unwrap();
    let first = device(ALICE, "alice-phone", 1, &dir)
        .stored_key_packages()
        .unwrap();
    assert!(!first.is_empty());
    let mut reopened = device(ALICE, "alice-phone", 1, &dir)
        .stored_key_packages()
        .unwrap();
    let mut first = first;
    first.sort();
    reopened.sort();
    assert_eq!(first, reopened);
}
