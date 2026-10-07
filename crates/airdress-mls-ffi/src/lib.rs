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

// `catch_unwind` around every export is what keeps a Rust panic from
// unwinding into Dart. Built with `panic = "abort"` it catches nothing,
// and a panic on hostile input aborts the app again — so that build is
// refused rather than shipped.
#[cfg(panic = "abort")]
compile_error!(
    "airdress-mls-ffi must be built with panic = \"unwind\": every export relies on catch_unwind"
);

// The FFI layer requires unsafe at the C boundary; the engine it wraps
// (in `airdress-mls`) remains safe Rust. Its exports are `pub` so they
// can be `extern "C"` symbols, not so Rust can name them.
#[expect(
    unsafe_code,
    reason = "the C ABI: raw pointers in, raw pointers out (R-UNS-1)"
)]
#[expect(
    unreachable_pub,
    reason = "the exports are reached by the dynamic linker, not by a Rust path"
)]
mod ffi;

pub use airdress_mls::*;
