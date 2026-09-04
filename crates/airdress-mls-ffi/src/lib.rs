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

pub mod canonical;
pub mod credential;
mod engine;

// The FFI layer requires unsafe at the C boundary, but the engine
// module (which holds all MLS logic) remains safe Rust.
#[allow(unsafe_code)]
mod ffi;
pub mod storage;

pub use engine::MlsEngine;

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
        let outcome = alice.start_group(&bob_kp, b"hello bob").unwrap();
        bob.process_welcome(&outcome.welcome).unwrap();
        assert_eq!(
            bob.decrypt(&outcome.group_id, &outcome.first_application)
                .unwrap(),
            b"hello bob"
        );

        // Encrypt BEFORE the restart; decrypt after reconstruction
        // from the same state_dir + state_key.
        let pre_restart = alice
            .encrypt(&outcome.group_id, b"sent before restart")
            .unwrap();
        drop(bob);
        let mut bob = engine_at("bob.test", 2, bob_dir.path());
        assert_eq!(
            bob.decrypt(&outcome.group_id, &pre_restart).unwrap(),
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
        let outcome = alice.start_group(&bob_kp, b"hi").unwrap();
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
        let msg = alice.encrypt(&outcome.group_id, b"again").unwrap();
        let err = match bob.decrypt(&outcome.group_id, &msg) {
            Err(e) => e,
            Ok(_) => panic!("corrupt state must refuse, not panic"),
        };
        assert!(err.contains("load group"), "unexpected error: {err}");
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
        let outcome = alice.start_group(&bob_kp, b"hello bob").unwrap();

        bob.process_welcome(&outcome.welcome).unwrap();

        let plaintext = bob
            .decrypt(&outcome.group_id, &outcome.first_application)
            .unwrap();
        assert_eq!(plaintext, b"hello bob");

        let bob_reply = bob.encrypt(&outcome.group_id, b"hi alice").unwrap();
        let alice_sees = alice.decrypt(&outcome.group_id, &bob_reply).unwrap();
        assert_eq!(alice_sees, b"hi alice");
    }
}
