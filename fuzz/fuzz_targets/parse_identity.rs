//! A leaf credential's identity bytes, as any group member can set them.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // Any answer is fine; a panic, a hang or an abort is the bug.
    drop(airdress_mls::credential::parse_identity(data));
});
