//! This crate's shared test vectors, compiled in so the phone's tests and
//! this crate's read the same bytes.

/// Lane payload decoding: plaintext → `{origin, blocks}` or refused.
pub const LANE_PAYLOAD: &str = include_str!("../../../vectors/lane_payload.json");

/// The commit-group tag: group id → 32 lowercase hex characters.
pub const COMMIT_GROUP: &str = include_str!("../../../vectors/commit_group.json");
