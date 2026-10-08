//! A group conversation's context extensions, as a peer chose them: what
//! parses must validate and re-encode to the same value.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    airdress_mls::fuzzing::group_extensions_decode(data);
});
