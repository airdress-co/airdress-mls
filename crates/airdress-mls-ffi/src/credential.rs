//! Delegation-carrying MLS credential.
//!
//! Per RDR-005 Amendment 1 §10.5 the credential stays a
//! `BasicCredential` — this module only defines what goes INTO its
//! identity bytes: the canonical JSON of
//!
//! ```json
//! { "v": 1,
//!   "airdress": "alice.humans.airdress.co",
//!   "root_public_key": "<b64url 32 bytes>",
//!   "delegation": { ...delegation object, signature included... } }
//! ```
//!
//! serialized with the same canonicalization as delegation signing
//! (`canonical.rs`): compact JSON, object keys sorted at every level.
//!
//! A legacy bare-string identity (a pre-cutover client) still parses,
//! so the loopback harness can exercise both forms. Detection is by
//! "parses as a JSON object with `v: 1`", never by heuristics on the
//! first byte.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};

/// The structured identity carried in the credential's identity bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AirdressIdentity {
    pub airdress: String,
    pub root_public_key: [u8; 32],
    /// The full delegation object, `signature` field included.
    pub delegation: Map<String, Value>,
}

impl AirdressIdentity {
    /// Serialize to the canonical identity bytes (v1 JSON form).
    pub fn to_identity_bytes(&self) -> Result<Vec<u8>, String> {
        let mut obj = Map::new();
        obj.insert("v".to_owned(), Value::from(1));
        obj.insert("airdress".to_owned(), Value::from(self.airdress.clone()));
        obj.insert(
            "root_public_key".to_owned(),
            Value::from(URL_SAFE_NO_PAD.encode(self.root_public_key)),
        );
        obj.insert(
            "delegation".to_owned(),
            Value::Object(self.delegation.clone()),
        );
        serde_json::to_vec(&Value::Object(obj))
            .map_err(|e| format!("identity serialization failed: {e}"))
    }
}

/// The two identity forms a peer leaf can carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedIdentity {
    /// New delegation-carrying JSON form (`v: 1`).
    V1(AirdressIdentity),
    /// Pre-cutover bare-string identity (the airdress itself).
    Legacy(String),
}

/// Parse credential identity bytes into one of the two forms.
///
/// Rules: bytes that parse as a JSON object with `"v": 1` are the new
/// form and must then be fully well-formed (an error, not a fallback,
/// otherwise). Anything else that is valid UTF-8 is a legacy
/// bare-string identity. Invalid UTF-8 is an error.
pub fn parse_identity(bytes: &[u8]) -> Result<ParsedIdentity, String> {
    if let Ok(Value::Object(obj)) = serde_json::from_slice::<Value>(bytes)
        && obj.get("v").and_then(Value::as_i64) == Some(1)
    {
        {
            let airdress = obj
                .get("airdress")
                .and_then(Value::as_str)
                .ok_or("identity missing 'airdress'")?
                .to_owned();
            let root_b64 = obj
                .get("root_public_key")
                .and_then(Value::as_str)
                .ok_or("identity missing 'root_public_key'")?;
            let root_public_key: [u8; 32] = URL_SAFE_NO_PAD
                .decode(root_b64)
                .map_err(|e| format!("identity root_public_key base64 decode failed: {e}"))?
                .try_into()
                .map_err(|_| "identity root_public_key is not 32 bytes".to_owned())?;
            let delegation = obj
                .get("delegation")
                .and_then(Value::as_object)
                .ok_or("identity missing 'delegation' object")?
                .clone();
            return Ok(ParsedIdentity::V1(AirdressIdentity {
                airdress,
                root_public_key,
                delegation,
            }));
        }
    }
    let legacy = std::str::from_utf8(bytes)
        .map_err(|_| "identity bytes are neither v1 JSON nor UTF-8".to_owned())?;
    Ok(ParsedIdentity::Legacy(legacy.to_owned()))
}

#[cfg(test)]
mod tests {
    use mls_rs::identity::basic::BasicCredential;
    use serde_json::{Value, json};

    use super::{AirdressIdentity, ParsedIdentity, parse_identity};

    fn fixture_identity() -> AirdressIdentity {
        // Vector "minimal-realistic" from the shared fixture.
        let parsed: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../airdress-common/tests/fixtures/delegation_vectors.json"
        )))
        .unwrap();
        let vector = &parsed["vectors"][0];
        assert_eq!(vector["name"], json!("minimal-realistic"));
        AirdressIdentity {
            airdress: "alice.humans.airdress.co".to_owned(),
            root_public_key: {
                use base64::Engine as _;
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(vector["root_public_key_b64url"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap()
            },
            delegation: vector["delegation"].as_object().unwrap().clone(),
        }
    }

    #[test]
    fn identity_bytes_match_fixture_and_round_trip() {
        let identity = fixture_identity();
        let bytes = identity.to_identity_bytes().unwrap();

        // Canonical shape: sorted keys, delegation embedded verbatim.
        let as_value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(as_value["v"], json!(1));
        assert_eq!(as_value["airdress"], json!("alice.humans.airdress.co"));
        assert_eq!(
            as_value["delegation"],
            Value::Object(identity.delegation.clone())
        );
        assert!(
            bytes.starts_with(b"{\"airdress\":"),
            "keys must serialize sorted"
        );

        match parse_identity(&bytes).unwrap() {
            ParsedIdentity::V1(back) => assert_eq!(back, identity),
            ParsedIdentity::Legacy(_) => panic!("v1 identity parsed as legacy"),
        }
    }

    #[test]
    fn identity_round_trips_through_mls_credential() {
        let identity = fixture_identity();
        let bytes = identity.to_identity_bytes().unwrap();
        let credential = BasicCredential::new(bytes.clone()).into_credential();
        let basic = credential.as_basic().expect("still a BasicCredential");
        assert_eq!(basic.identifier, bytes);
        match parse_identity(&basic.identifier).unwrap() {
            ParsedIdentity::V1(back) => assert_eq!(back, identity),
            ParsedIdentity::Legacy(_) => panic!("v1 identity parsed as legacy"),
        }
    }

    #[test]
    fn legacy_bare_string_still_parses() {
        match parse_identity(b"alice.humans.airdress.co").unwrap() {
            ParsedIdentity::Legacy(s) => assert_eq!(s, "alice.humans.airdress.co"),
            ParsedIdentity::V1(_) => panic!("bare string parsed as v1"),
        }
    }

    #[test]
    fn json_object_without_v1_is_legacy_not_v1() {
        // Detection is "JSON object with v:1", so an object without it
        // falls through to the legacy branch (it is valid UTF-8).
        let bytes = br#"{"airdress":"alice.test"}"#;
        match parse_identity(bytes).unwrap() {
            ParsedIdentity::Legacy(s) => assert_eq!(s.as_bytes(), bytes),
            ParsedIdentity::V1(_) => panic!("object without v:1 must not be v1"),
        }
    }

    #[test]
    fn v1_object_with_bad_fields_is_an_error_not_legacy() {
        let bytes = br#"{"v":1,"airdress":"alice.test"}"#;
        assert!(parse_identity(bytes).is_err());
    }

    #[test]
    fn invalid_utf8_is_an_error() {
        assert!(parse_identity(&[0xff, 0xfe, 0x01]).is_err());
    }
}
