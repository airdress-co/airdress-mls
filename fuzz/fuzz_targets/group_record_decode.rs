//! A group's sealed record after unsealing: what decodes must re-encode
//! to the same bytes.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    airdress_mls::fuzzing::group_record_round_trip(data);
});
