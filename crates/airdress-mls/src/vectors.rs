//! The shared test vectors, compiled in so a consumer's tests read the
//! same bytes this crate's tests read.
//!
//! A consumer that keeps its own copy of a vector file has two vector
//! sets that agree on the day they were copied. Reading them from here
//! leaves one.

/// Delegation canonicalization vectors: each carries a delegation object
/// and `canonical_b64url`, the exact Ed25519 signing input.
pub const DELEGATION: &str = include_str!("../../../vectors/delegation_vectors.json");
