//! A decrypted application message's plaintext: chosen by the peer that
//! sent it, read before anything else looks at it.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    drop(airdress_mls_client::LanePayload::decode(data));
});
