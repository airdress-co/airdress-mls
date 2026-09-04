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
mod engine;

// The FFI layer requires unsafe at the C boundary, but the engine
// module (which holds all MLS logic) remains safe Rust.
#[allow(unsafe_code)]
mod ffi;

pub use engine::MlsEngine;

#[cfg(test)]
mod tests {
    use super::engine::MlsEngine;

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
