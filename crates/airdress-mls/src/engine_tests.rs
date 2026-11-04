//! The engine's staged proposals, held commits and key-package pool,
//! through real engines past the cutover:
//!
//! - a batch of proposals staged at one epoch is not carried out at
//!   another, where a leaf index can name someone else;
//! - a held commit is confirmed onto the group as it is on disk then, so a
//!   key used while it waited stays used;
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
    engine.set_revocation_lookup(Arc::new(|_: &str, _: &str| Some(DeviceStatus::Active)));
    engine.set_v2_cutover();
    engine
}

/// Commit what `by` staged, confirm it, and apply it on every other
/// member; a Welcome, if any, is returned.
fn commit_everywhere(
    by: &mut MlsEngine,
    others: &mut [&mut MlsEngine],
    group: &[u8],
) -> Option<Vec<u8>> {
    let c = by.commit_pending(group).unwrap();
    by.confirm_commit(group).unwrap();
    for other in others.iter_mut() {
        other.process_commit(group, &c.commit).unwrap();
    }
    c.welcome
}

fn index_of(engine: &MlsEngine, group: &[u8], device_name: &str) -> Option<u32> {
    engine
        .group_members(group)
        .unwrap()
        .into_iter()
        .find(|m| m.identity.ends_with(device_name.as_bytes()))
        .map(|m| m.index)
}

#[test]
fn a_staged_removal_from_an_earlier_epoch_is_not_carried_out() {
    let dirs: Vec<_> = (0..5).map(|_| tempfile::tempdir().unwrap()).collect();
    let mut phone = device(ALICE, "alice-phone", 1, &dirs[0]);
    let mut bob = device(BOB, "bob-phone", 2, &dirs[1]);
    let mut tablet = device(ALICE, "alice-tablet", 3, &dirs[2]);
    let mut laptop = device(ALICE, "alice-laptop", 4, &dirs[3]);
    let mut desk = device(ALICE, "alice-desk", 5, &dirs[4]);

    let out = phone
        .start_group(&bob.generate_key_package().unwrap(), b"hi", ALICE)
        .unwrap();
    let group = out.group_id.clone();
    bob.process_welcome(&out.welcome).unwrap();
    phone
        .propose_add(&group, &tablet.generate_key_package().unwrap())
        .unwrap();
    phone
        .propose_add(&group, &laptop.generate_key_package().unwrap())
        .unwrap();
    let welcome = commit_everywhere(&mut phone, &mut [&mut bob], &group).unwrap();
    tablet.process_welcome(&welcome).unwrap();
    laptop.process_welcome(&welcome).unwrap();

    // The phone stages the laptop's removal, checked against this roster.
    let laptop_leaf = index_of(&phone, &group, "alice-laptop").unwrap();
    phone.propose_remove(&group, laptop_leaf).unwrap();

    // Meanwhile the tablet removes the laptop and adds the desk, which
    // RFC 9420 puts in the leaf the laptop left.
    tablet.propose_remove(&group, laptop_leaf).unwrap();
    tablet
        .propose_add(&group, &desk.generate_key_package().unwrap())
        .unwrap();
    let welcome = commit_everywhere(&mut tablet, &mut [&mut phone, &mut bob], &group).unwrap();
    desk.process_welcome(&welcome).unwrap();
    assert_eq!(index_of(&phone, &group, "alice-desk"), Some(laptop_leaf));

    // The removal staged at the earlier epoch is refused, not applied to
    // whoever holds the leaf now, and it is dropped.
    assert!(
        phone.commit_pending(&group).is_err(),
        "a removal staged at an earlier epoch was committed"
    );
    commit_everywhere(&mut phone, &mut [&mut bob, &mut tablet, &mut desk], &group);
    assert_eq!(index_of(&phone, &group, "alice-desk"), Some(laptop_leaf));
}

/// Alice's phone and Bob's phone in one group.
fn pair(dirs: &[tempfile::TempDir]) -> (MlsEngine, MlsEngine, Vec<u8>) {
    let mut phone = device(ALICE, "alice-phone", 1, &dirs[0]);
    let mut bob = device(BOB, "bob-phone", 2, &dirs[1]);
    let out = phone
        .start_group(&bob.generate_key_package().unwrap(), b"hi", ALICE)
        .unwrap();
    bob.process_welcome(&out.welcome).unwrap();
    (phone, bob, out.group_id)
}

#[test]
fn a_key_used_while_a_commit_waits_stays_used_after_confirmation() {
    let dirs: Vec<_> = (0..2).map(|_| tempfile::tempdir().unwrap()).collect();
    let (mut phone, mut bob, group) = pair(&dirs);

    let message = bob.encrypt(&group, b"while you commit", BOB).unwrap();
    let held = phone.commit_pending(&group).unwrap();
    assert_eq!(
        phone.decrypt(&group, &message, BOB).unwrap(),
        b"while you commit"
    );
    let epoch = phone.confirm_commit(&group).unwrap();
    assert_eq!(epoch, held.epoch);

    assert!(
        phone.decrypt(&group, &message, BOB).is_err(),
        "a message key used before confirmation was restored by it"
    );

    // The confirmed epoch is the one Bob reaches, and both still talk.
    assert_eq!(
        bob.process_commit(&group, &held.commit).unwrap().epoch,
        epoch
    );
    let reply = bob.encrypt(&group, b"after", BOB).unwrap();
    assert_eq!(phone.decrypt(&group, &reply, BOB).unwrap(), b"after");
    let back = phone.encrypt(&group, b"and back", ALICE).unwrap();
    assert_eq!(bob.decrypt(&group, &back, ALICE).unwrap(), b"and back");
}

#[test]
fn a_commit_built_before_the_group_moved_on_is_not_confirmed() {
    let dirs: Vec<_> = (0..2).map(|_| tempfile::tempdir().unwrap()).collect();
    let (mut phone, mut bob, group) = pair(&dirs);

    phone.commit_pending(&group).unwrap();
    let theirs = bob.commit_pending(&group).unwrap();
    bob.confirm_commit(&group).unwrap();
    phone.process_commit(&group, &theirs.commit).unwrap();

    assert!(phone.confirm_commit(&group).is_err());
    assert_eq!(phone.group_epoch(&group), Some(theirs.epoch));
    let message = bob.encrypt(&group, b"still together", BOB).unwrap();
    assert_eq!(
        phone.decrypt(&group, &message, BOB).unwrap(),
        b"still together"
    );
}

/// A held commit whose confirmation could not be written stays held, and
/// confirms once storage takes the write: the operator has accepted it,
/// and the held commit is the only copy of the new epoch's secrets.
#[test]
fn a_commit_whose_confirmation_could_not_be_written_stays_held() {
    use std::os::unix::fs::PermissionsExt as _;
    let dirs: Vec<_> = (0..2).map(|_| tempfile::tempdir().unwrap()).collect();
    let (mut phone, mut bob, group) = pair(&dirs);
    let held = phone.commit_pending(&group).unwrap();

    let groups = dirs[0].path().join("groups");
    std::fs::set_permissions(&groups, std::fs::Permissions::from_mode(0o555)).unwrap();
    let refused = phone.confirm_commit(&group);
    std::fs::set_permissions(&groups, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        matches!(refused, Err(super::EngineError::Storage(_))),
        "{refused:?}"
    );
    assert_eq!(phone.group_epoch(&group), Some(held.epoch - 1));
    assert!(
        phone.commit_pending(&group).is_err(),
        "the commit is still awaiting confirmation"
    );

    assert_eq!(phone.confirm_commit(&group).unwrap(), held.epoch);
    bob.process_commit(&group, &held.commit).unwrap();
    let message = bob.encrypt(&group, b"in the new epoch", BOB).unwrap();
    assert_eq!(
        phone.decrypt(&group, &message, BOB).unwrap(),
        b"in the new epoch"
    );
}

#[test]
fn aborting_with_no_commit_pending_still_drops_what_was_staged() {
    let dirs: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
    let (mut phone, mut bob, group) = pair(&dirs);
    let tablet = device(ALICE, "alice-tablet", 3, &dirs[2]);

    phone
        .propose_add(&group, &tablet.generate_key_package().unwrap())
        .unwrap();
    assert!(phone.abort_commit(&group).is_err(), "nothing was pending");

    let c = phone.commit_pending(&group).unwrap();
    assert!(
        c.added.is_empty(),
        "the aborted batch rode on the next commit"
    );
    phone.confirm_commit(&group).unwrap();
    bob.process_commit(&group, &c.commit).unwrap();
}

/// A key package made the way an engine made them before it advertised
/// the group extension types: the same store, no `extension_types`.
fn store_a_package_without_group_extensions(dir: &tempfile::TempDir) {
    store_a_package_without_group_extensions_under(dir, &STATE_KEY);
}

/// The same, sealed under `state_key`.
fn store_a_package_without_group_extensions_under(dir: &tempfile::TempDir, state_key: &[u8; 32]) {
    let store =
        SealedKeyPackageStore(SealedStore::open(dir.path().to_str().unwrap(), state_key).unwrap());
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

/// A pooled key package this device cannot unseal (damaged, or sealed
/// under another key) is left alone at open, as before the sweep: it
/// fails on its own when used, and the engine still opens.
#[test]
fn opening_skips_a_key_package_it_cannot_read() {
    let dir = tempfile::tempdir().unwrap();
    let current = device(ALICE, "alice-phone", 1, &dir)
        .stored_key_packages()
        .unwrap();
    store_a_package_without_group_extensions_under(&dir, &[8u8; 32]);
    let files = |sub: &str| std::fs::read_dir(dir.path().join(sub)).unwrap().count();
    let (private, public) = (files("key_packages"), files("key_packages_public"));

    let engine = device(ALICE, "alice-phone", 1, &dir);
    assert_eq!(
        engine.stored_key_packages().unwrap(),
        current,
        "the unreadable package is not handed out"
    );
    assert_eq!(
        files("key_packages"),
        private,
        "the unreadable half was deleted"
    );
    assert_eq!(files("key_packages_public"), public);
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
