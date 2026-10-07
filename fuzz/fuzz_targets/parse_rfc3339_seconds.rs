//! A delegation's `issued_at` / `expires_at`, as the delegation's signer
//! wrote them.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        std::hint::black_box(airdress_mls::fuzzing::parse_rfc3339_seconds(s));
    }
});
