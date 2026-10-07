//! An inbound MLS message's framing, read before any key is used.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    drop(airdress_mls::engine::message_group_id(data));
});
