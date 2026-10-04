//! C ABI over [`airdress_mls`] — what the phone's Dart calls via
//! `dart:ffi`.
//!
//! ## Architecture
//!
//! Engines are stored in a global handle table. Dart holds integer handle
//! IDs and passes them to every operation. Byte buffers cross the FFI
//! boundary via `FfiBytes` (pointer + length), allocated by Rust and freed
//! by Dart calling `airdress_mls_free_bytes`.
//!
//! The exported set is `symbols.txt` beside `Cargo.toml`. CI builds the
//! shared library and compares its dynamic symbol table to that list in
//! both directions, so an export added here without the list (or the
//! other way round) fails before it reaches a phone.

// The FFI layer requires unsafe at the C boundary; the engine it wraps
// (in `airdress-mls`) remains safe Rust.
#[allow(unsafe_code)]
mod ffi;

pub use airdress_mls::*;
