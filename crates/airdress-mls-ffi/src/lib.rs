//! C-FFI wrapper for `mls-rs` — exposes MLS operations to Dart via `dart:ffi`.
//!
//! ## Architecture
//!
//! Engines are stored in a global handle table. Dart holds integer handle
//! IDs and passes them to every operation. Byte buffers cross the FFI
//! boundary via `FfiBytes` (pointer + length), allocated by Rust and freed
//! by Dart calling `airdress_mls_free_bytes`.
//!
//! ## Ciphersuite
//!
//! CS3 (`MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`) — same as
//! the operator's `agent/mls.rs`.

pub mod binding;
pub mod canonical;
pub mod credential;
mod engine;
pub mod rules;

// The FFI layer requires unsafe at the C boundary, but the engine
// module (which holds all MLS logic) remains safe Rust.
#[allow(unsafe_code)]
mod ffi;
pub mod storage;

pub use binding::MessageBinding;
pub use engine::{CommitOutcome, EngineError, GroupMember, MlsEngine};

#[cfg(test)]
mod tests {
    use super::engine::MlsEngine;

    /// Deterministic engine over a caller-owned state dir.
    fn engine_at(airdress: &str, seed_byte: u8, state_dir: &std::path::Path) -> MlsEngine {
        let seed = [seed_byte; 32];
        let root = ed25519_dalek::SigningKey::from_bytes(&[seed_byte.wrapping_add(100); 32]);
        let session_pub = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let delegation =
            crate::credential::test_support::signed_delegation_json(&root, airdress, &session_pub);
        MlsEngine::from_seed(
            airdress,
            &seed,
            &root.verifying_key().to_bytes(),
            &delegation,
            state_dir.to_str().unwrap(),
            &[77u8; 32],
        )
        .unwrap()
    }

    #[test]
    fn state_survives_engine_restart() {
        let alice_dir = tempfile::tempdir().unwrap();
        let bob_dir = tempfile::tempdir().unwrap();

        let mut alice = engine_at("alice.test", 1, alice_dir.path());
        let mut bob = engine_at("bob.test", 2, bob_dir.path());

        let bob_kp = bob.generate_key_package().unwrap();
        let outcome = alice.start_group(&bob_kp, b"hello bob", "").unwrap();
        bob.process_welcome(&outcome.welcome).unwrap();
        assert_eq!(
            bob.decrypt(&outcome.group_id, &outcome.first_application, "")
                .unwrap(),
            b"hello bob"
        );

        // Encrypt BEFORE the restart; decrypt after reconstruction
        // from the same state_dir + state_key.
        let pre_restart = alice
            .encrypt(&outcome.group_id, b"sent before restart", "")
            .unwrap();
        drop(bob);
        let mut bob = engine_at("bob.test", 2, bob_dir.path());
        assert_eq!(
            bob.decrypt(&outcome.group_id, &pre_restart, "").unwrap(),
            b"sent before restart"
        );
    }

    #[test]
    fn corrupted_group_state_is_refused_cleanly() {
        let alice_dir = tempfile::tempdir().unwrap();
        let bob_dir = tempfile::tempdir().unwrap();
        let mut alice = engine_at("alice.test", 3, alice_dir.path());
        let mut bob = engine_at("bob.test", 4, bob_dir.path());

        let bob_kp = bob.generate_key_package().unwrap();
        let outcome = alice.start_group(&bob_kp, b"hi", "").unwrap();
        bob.process_welcome(&outcome.welcome).unwrap();

        // Corrupt bob's sealed group file.
        let groups_dir = bob_dir.path().join("groups");
        let entry = std::fs::read_dir(&groups_dir)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let mut bytes = std::fs::read(entry.path()).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(entry.path(), bytes).unwrap();

        drop(bob);
        let mut bob = engine_at("bob.test", 4, bob_dir.path());
        let msg = alice.encrypt(&outcome.group_id, b"again", "").unwrap();
        let err = match bob.decrypt(&outcome.group_id, &msg, "") {
            Err(e) => e,
            Ok(_) => panic!("corrupt state must refuse, not panic"),
        };
        let err = err.to_string();
        assert!(err.contains("load group"), "unexpected error: {err}");
    }

    #[test]
    fn pool_established_at_first_init_and_only_then() {
        let dir = tempfile::tempdir().unwrap();
        let bob = engine_at("bob.test", 5, dir.path());
        assert_eq!(
            bob.key_package_pool_count().unwrap(),
            crate::engine::INITIAL_KEY_PACKAGE_POOL
        );
        assert_eq!(
            bob.stored_key_packages().unwrap().len(),
            crate::engine::INITIAL_KEY_PACKAGE_POOL
        );

        // A restart must NOT regenerate — the existing pool survives.
        drop(bob);
        let bob = engine_at("bob.test", 5, dir.path());
        assert_eq!(
            bob.key_package_pool_count().unwrap(),
            crate::engine::INITIAL_KEY_PACKAGE_POOL
        );

        // Explicit generation refills on top.
        let extra = bob.generate_key_packages(2).unwrap();
        assert_eq!(extra.len(), 2);
        assert_eq!(
            bob.key_package_pool_count().unwrap(),
            crate::engine::INITIAL_KEY_PACKAGE_POOL + 2
        );
    }

    #[test]
    fn welcome_against_pre_restart_key_package_joins_after_restart() {
        let alice_dir = tempfile::tempdir().unwrap();
        let bob_dir = tempfile::tempdir().unwrap();
        let mut alice = engine_at("alice.test", 6, alice_dir.path());
        let bob = engine_at("bob.test", 7, bob_dir.path());

        // Take a publishable package from bob's persisted pool, then
        // restart bob BEFORE the Welcome arrives.
        let bob_kp = bob.stored_key_packages().unwrap().pop().unwrap();
        let pool_before = bob.key_package_pool_count().unwrap();
        drop(bob);
        let mut bob = engine_at("bob.test", 7, bob_dir.path());

        let outcome = alice
            .start_group(&bob_kp, b"welcome across restart", "")
            .unwrap();
        bob.process_welcome(&outcome.welcome).unwrap();
        assert_eq!(
            bob.decrypt(&outcome.group_id, &outcome.first_application, "")
                .unwrap(),
            b"welcome across restart"
        );

        // Single-use: joining consumed the package.
        assert_eq!(bob.key_package_pool_count().unwrap(), pool_before - 1);
    }

    #[test]
    fn same_seed_same_public_key() {
        let seed = [42u8; 32];
        let root = [1u8; 32];
        let delegation = r#"{"airdress":"alice.test"}"#;
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let a = MlsEngine::from_seed(
            "alice.test",
            &seed,
            &root,
            delegation,
            dir_a.path().to_str().unwrap(),
            &[3u8; 32],
        )
        .unwrap();
        let b = MlsEngine::from_seed(
            "alice.test",
            &seed,
            &root,
            delegation,
            dir_b.path().to_str().unwrap(),
            &[3u8; 32],
        )
        .unwrap();
        assert_eq!(a.public_key(), b.public_key());
    }

    #[test]
    fn from_seed_rejects_non_object_delegation() {
        let dir = tempfile::tempdir().unwrap();
        let err = MlsEngine::from_seed(
            "alice.test",
            &[42u8; 32],
            &[1u8; 32],
            "[1,2,3]",
            dir.path().to_str().unwrap(),
            &[3u8; 32],
        );
        let err = err.err().expect("non-object delegation must be rejected");
        assert!(err.contains("JSON object"), "unexpected error: {err}");
    }

    #[test]
    fn round_trip_welcome_and_application() {
        let mut alice = MlsEngine::new("alice.test").unwrap();
        let mut bob = MlsEngine::new("bob.test").unwrap();

        let bob_kp = bob.generate_key_package().unwrap();
        let outcome = alice.start_group(&bob_kp, b"hello bob", "").unwrap();

        bob.process_welcome(&outcome.welcome).unwrap();

        let plaintext = bob
            .decrypt(&outcome.group_id, &outcome.first_application, "")
            .unwrap();
        assert_eq!(plaintext, b"hello bob");

        let bob_reply = bob.encrypt(&outcome.group_id, b"hi alice", "").unwrap();
        let alice_sees = alice.decrypt(&outcome.group_id, &bob_reply, "").unwrap();
        assert_eq!(alice_sees, b"hi alice");
    }

    // -----------------------------------------------------------------
    // SPEC-061 Phase 1 — storage safety
    // -----------------------------------------------------------------

    /// SPEC-061 AC-2 / FR-21 / FR-22.
    ///
    /// A group advanced well past the retention bound keeps at most
    /// `max_epoch_retention` past-epoch records on disk, and a
    /// ciphertext captured at epoch 1 fails on a RESTARTED engine with
    /// the distinguishable error — not a generic decrypt failure.
    ///
    /// Fails before Phase 1: `storage.rs` appended epoch records
    /// without limit, so all 20 survived and the epoch-1 ciphertext
    /// decrypted happily.
    #[test]
    fn epoch_retention_is_bounded_and_trimmed_epochs_are_distinguishable() {
        use crate::engine::EngineError;

        let alice_dir = tempfile::tempdir().unwrap();
        let bob_dir = tempfile::tempdir().unwrap();

        let mut alice = engine_at("alice.test", 21, alice_dir.path());
        let mut bob = engine_at("bob.test", 22, bob_dir.path());

        let bob_kp = bob.generate_key_package().unwrap();
        let outcome = alice.start_group(&bob_kp, b"hello bob", "").unwrap();
        let group_id = outcome.group_id.clone();
        bob.process_welcome(&outcome.welcome).unwrap();
        assert_eq!(
            bob.decrypt(&group_id, &outcome.first_application, "")
                .unwrap(),
            b"hello bob"
        );

        // A ciphertext from the group's first epoch, captured now and
        // replayed at the end — the "attacker with the sealed file"
        // row of the requirements threat table.
        let early_epoch = bob.group_epoch(&group_id).expect("bob is in the group");
        let early_ciphertext = alice
            .encrypt(&group_id, b"the first thing said", "")
            .unwrap();

        // Advance 20 epochs with real commits (Phase 4 replaced the
        // `test_only_advance_epoch` / `test_only_process_commit`
        // scaffolding this test used to need). Alice commits and
        // confirms; Bob applies.
        for _ in 0..20 {
            let outcome = alice.commit_pending(&group_id).unwrap();
            alice.confirm_commit(&group_id).unwrap();
            let applied = bob.process_commit(&group_id, &outcome.commit).unwrap();
            assert_eq!(applied.epoch, outcome.epoch);
            assert!(!applied.self_removed);
        }

        let retained = bob.group_store().retained_epoch_ids(&group_id).unwrap();
        assert!(
            retained.len() <= crate::storage::DEFAULT_MAX_EPOCH_RETENTION,
            "20 epochs advanced but {} epoch records are on disk: {retained:?}",
            retained.len()
        );
        assert!(
            !retained.contains(&early_epoch),
            "the first epoch's secrets are still on disk: {retained:?}"
        );

        // Restart: nothing here depends on an in-memory view.
        drop(bob);
        let mut bob = engine_at("bob.test", 22, bob_dir.path());
        let retained = bob.group_store().retained_epoch_ids(&group_id).unwrap();
        assert!(retained.len() <= crate::storage::DEFAULT_MAX_EPOCH_RETENTION);

        let err = bob
            .decrypt(&group_id, &early_ciphertext, "")
            .expect_err("a trimmed epoch must not decrypt");
        match err {
            EngineError::EpochUnavailable {
                requested,
                oldest_retained,
            } => {
                assert_eq!(requested, early_epoch);
                assert_eq!(
                    oldest_retained,
                    Some(*retained.first().expect("some epoch is retained"))
                );
                assert!(oldest_retained.unwrap() > requested);
            }
            other => panic!("expected EpochUnavailable, got {other:?}"),
        }
    }

    /// A message from an epoch that is still retained fails, if it
    /// fails at all, as an ordinary error — `EpochUnavailable` must not
    /// become the answer to every decrypt problem.
    #[test]
    fn a_corrupt_message_is_not_reported_as_a_trimmed_epoch() {
        use crate::engine::EngineError;

        let alice_dir = tempfile::tempdir().unwrap();
        let bob_dir = tempfile::tempdir().unwrap();
        let mut alice = engine_at("alice.test", 23, alice_dir.path());
        let mut bob = engine_at("bob.test", 24, bob_dir.path());

        let bob_kp = bob.generate_key_package().unwrap();
        let outcome = alice.start_group(&bob_kp, b"hello bob", "").unwrap();
        bob.process_welcome(&outcome.welcome).unwrap();
        bob.decrypt(&outcome.group_id, &outcome.first_application, "")
            .unwrap();

        let mut ciphertext = alice
            .encrypt(&outcome.group_id, b"current epoch", "")
            .unwrap();
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0x01;
        let err = bob
            .decrypt(&outcome.group_id, &ciphertext, "")
            .expect_err("a mangled message must not decrypt");
        assert!(
            !matches!(err, EngineError::EpochUnavailable { .. }),
            "a current-epoch failure was mislabelled as a trimmed epoch: {err:?}"
        );
    }

    /// SPEC-061 AC-12 / FR-24 / design D-9.
    ///
    /// A Commit delivered on the application path is rejected AND
    /// leaves the on-disk epoch exactly where it was.
    ///
    /// Fails before Phase 1: `decrypt` called `write_to_storage()`
    /// before matching on the kind, so mls-rs applied the commit, the
    /// engine sealed the advanced state, and only then returned "not
    /// an application message".
    #[test]
    fn a_commit_on_the_application_path_does_not_advance_the_stored_epoch() {
        use mls_rs_core::group::GroupStateStorage as _;

        let alice_dir = tempfile::tempdir().unwrap();
        let bob_dir = tempfile::tempdir().unwrap();

        let mut alice = engine_at("alice.test", 25, alice_dir.path());
        let mut bob = engine_at("bob.test", 26, bob_dir.path());

        let bob_kp = bob.generate_key_package().unwrap();
        let outcome = alice.start_group(&bob_kp, b"hello bob", "").unwrap();
        let group_id = outcome.group_id.clone();
        bob.process_welcome(&outcome.welcome).unwrap();
        bob.decrypt(&group_id, &outcome.first_application, "")
            .unwrap();

        let epoch_before = bob.group_epoch(&group_id).expect("bob is in the group");
        let max_epoch_before = bob.group_store().max_epoch_id(&group_id).unwrap();

        // A genuine Commit, misrouted onto the application path. It
        // is built but never confirmed, so Alice's own sealed state is
        // untouched too — the two-phase shape (FR-7) makes producing
        // one for this test a normal operation rather than scaffolding.
        let commit = alice.commit_pending(&group_id).unwrap().commit;
        alice.abort_commit(&group_id).unwrap();
        let err = bob
            .decrypt(&group_id, &commit, "")
            .expect_err("a commit is not an application message");
        assert_eq!(err.to_string(), "not an application message");

        assert_eq!(
            bob.group_store().max_epoch_id(&group_id).unwrap(),
            max_epoch_before,
            "the misrouted commit advanced max_epoch_id on disk"
        );
        assert_eq!(
            bob.group_epoch(&group_id),
            Some(epoch_before),
            "the misrouted commit advanced the stored group epoch"
        );

        // And the group is still usable at the epoch it was left at.
        let msg = alice.encrypt(&group_id, b"still working", "").unwrap();
        assert_eq!(bob.decrypt(&group_id, &msg, "").unwrap(), b"still working");
    }

    /// A staged `Add` the commit builder refuses must not outlive the
    /// failed build: it used to stay staged with no way to clear it
    /// (`abort_commit` refuses when nothing is pending), so every later
    /// commit on the group failed on the same proposal. SPEC-111 phase A.
    #[test]
    fn a_commit_that_fails_to_build_drops_what_was_staged() {
        let alice_dir = tempfile::tempdir().unwrap();
        let bob_dir = tempfile::tempdir().unwrap();

        let mut alice = engine_at("alice.test", 27, alice_dir.path());
        let mut bob = engine_at("bob.test", 28, bob_dir.path());

        let bob_kp = bob.generate_key_package().unwrap();
        let outcome = alice.start_group(&bob_kp, b"hello bob", "").unwrap();
        let group_id = outcome.group_id.clone();
        bob.process_welcome(&outcome.welcome).unwrap();

        // Parses as an MLS message, so `propose_add` accepts it, and is
        // not a KeyPackage, so the builder refuses it — the cheapest
        // stand-in for a package the identity rules reject.
        alice.propose_add(&group_id, &outcome.welcome).unwrap();
        let err = alice
            .commit_pending(&group_id)
            .expect_err("a Welcome is not a member to add");
        assert!(err.starts_with("add member:"), "{err}");
        assert!(
            alice.abort_commit(&group_id).is_err(),
            "nothing is pending after a build that failed"
        );

        // The refused proposal is gone: the next commit is the plain
        // self-commit, and it reaches Bob.
        let commit = alice
            .commit_pending(&group_id)
            .expect("the failed Add did not poison the group")
            .commit;
        let epoch = alice.confirm_commit(&group_id).unwrap();
        let applied = bob.process_commit(&group_id, &commit).unwrap();
        assert_eq!(applied.epoch, epoch);
        assert!(applied.added.is_empty());
    }
}
