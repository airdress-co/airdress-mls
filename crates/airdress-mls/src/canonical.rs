//! Delegation canonicalization — client-side copy of the shared
//! contract.
//!
//! This function must stay byte-identical to
//! `airdress_common::delegation::canonical_delegation_bytes`. The two
//! crates deliberately do NOT share a dependency: `airdress-common`
//! pulls tokio/reqwest/figment into its tree, none of which belong in
//! a `cdylib` built for four Android ABIs and two iOS targets. The
//! byte-level agreement is enforced instead by the shared fixture at
//! `vectors/delegation_vectors.json` in this repository (exposed as
//! [`crate::vectors::DELEGATION`]), which both crates test against.
//!
//! # RFC 8785 subset — do not widen, do not enable `preserve_order`
//!
//! Keys sort at every nesting level via serde_json's default BTreeMap
//! representation; numbers and strings keep serde_json's default
//! formatting (so this is not full JCS). Widening toward full JCS is
//! a breaking change to every stored delegation signature, and
//! enabling serde_json's `preserve_order` feature would silently
//! change the bytes. See the shared helper's doc comment in
//! `airdress-common` for the full rationale.

use serde_json::{Map, Value};

/// Compute the canonical signing input for a delegation object: the
/// object minus its top-level `"signature"` field, keys sorted
/// lexicographically, serialized as compact JSON.
pub fn canonical_delegation_bytes(obj: &Map<String, Value>) -> Result<Vec<u8>, serde_json::Error> {
    let mut signing_obj: Map<String, Value> = obj
        .iter()
        .filter(|(k, _)| k.as_str() != "signature")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    // No-op with the default map representation (already sorted);
    // load-bearing only if `preserve_order` ever leaks in.
    signing_obj.sort_keys();
    serde_json::to_vec(&Value::Object(signing_obj))
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Verifier as _, VerifyingKey};
    use serde_json::Value;

    use super::canonical_delegation_bytes;

    /// The shared cross-crate fixture — see module docs.
    const FIXTURE: &str = crate::vectors::DELEGATION;

    #[test]
    fn matches_shared_delegation_vectors() {
        let parsed: Value = serde_json::from_str(FIXTURE).expect("fixture parses");
        let vectors = parsed["vectors"].as_array().expect("vectors array");
        assert!(vectors.len() >= 10, "fixture must hold at least 10 vectors");

        for vector in vectors {
            let name = vector["name"].as_str().expect("name");
            let delegation = vector["delegation"].as_object().expect("delegation");
            let expected = URL_SAFE_NO_PAD
                .decode(vector["canonical_b64url"].as_str().expect("canonical"))
                .expect("canonical decodes");

            let actual = canonical_delegation_bytes(delegation).expect("canonicalize");
            assert_eq!(actual, expected, "canonical bytes diverge for {name}");

            // And the vector's signature verifies over those bytes with
            // the vector's root key — the full client-side check.
            let root_pk: [u8; 32] = URL_SAFE_NO_PAD
                .decode(vector["root_public_key_b64url"].as_str().expect("root pk"))
                .expect("root pk decodes")
                .try_into()
                .expect("root pk is 32 bytes");
            let sig: [u8; 64] = URL_SAFE_NO_PAD
                .decode(delegation["signature"].as_str().expect("signature"))
                .expect("signature decodes")
                .try_into()
                .expect("signature is 64 bytes");
            VerifyingKey::from_bytes(&root_pk)
                .expect("valid root key")
                .verify(&actual, &ed25519_dalek::Signature::from_bytes(&sig))
                .unwrap_or_else(|e| panic!("signature invalid for {name}: {e}"));
        }
    }
}
