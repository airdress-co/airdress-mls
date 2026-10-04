//! Minting a delegation for an agent device.
//!
//! An agent device (a coding assistant's session host on a developer's
//! machine) never holds the airdress root. A device that does — the
//! person's phone — signs a delegation naming the agent's own Ed25519
//! key, and that delegation is everything the agent has: its MLS
//! credential chains to the root through it, and the operator admits
//! the agent on it.
//!
//! What the root signs, all inside the signed bytes:
//!
//! | Field | Value |
//! |-------|-------|
//! | `airdress` | the airdress the agent acts on |
//! | `device_class` | `"agent"` — what the operator fences on |
//! | `device_kind` | `"agent"` — the word every delegation-only device signs |
//! | `device_id` | the agent's stable device id |
//! | `device_label` | what people are shown, e.g. "Claude Code on build-host" |
//! | `device_session_public_key` | the agent's Ed25519 key (base64url) |
//! | `harness` | which program runs the agent, as data (`"claude-code"`) |
//! | `issued_at` / `expires_at` | RFC 3339, thirty days apart |
//! | `role` | `"human_held"` — the enrollment role a client-held device takes |
//!
//! Thirty days, not the human device's 180, and the device cannot
//! re-mint it: it holds no root. Renewal is a person approving again on
//! a device that does. The lifetime is fixed here rather than chosen by
//! the caller so every approver mints the same one.
//!
//! The delegation carries `device_id` and `expires_at`, so it reads as a
//! `v: 2` identity delegation ([`crate::credential::AirdressIdentity::from_delegation`]),
//! which is what an MLS member needs.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde_json::{Map, Value};
use zeroize::Zeroize as _;

/// How long an agent delegation lasts: thirty days.
pub const AGENT_DELEGATION_LIFETIME_SECS: u64 = 30 * 24 * 60 * 60;

/// From how long before expiry an agent device asks to be renewed:
/// seven days. The device cannot re-mint, so it asks early enough for a
/// person to answer.
pub const AGENT_DELEGATION_RENEW_WINDOW_SECS: u64 = 7 * 24 * 60 * 60;

/// The `device_class` (and `device_kind`) an agent delegation signs.
pub const AGENT_DEVICE_CLASS: &str = "agent";

/// Longest label an approver will sign: what a deciding screen renders.
pub const MAX_DEVICE_LABEL_CHARS: usize = 80;

/// What the root is asked to sign about one agent device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDelegationRequest<'a> {
    pub airdress: &'a str,
    /// `[A-Za-z0-9-]{1,64}`; a UUID fits.
    pub device_id: &'a str,
    /// The agent's Ed25519 identity key, which is also its MLS signing key.
    pub device_public_key: [u8; 32],
    /// `[a-z][a-z0-9-]{0,31}`, e.g. `claude-code`. Data, never an identifier.
    pub harness: &'a str,
    /// 1 to 80 characters, no surrounding whitespace, no control characters.
    pub device_label: &'a str,
    /// Seconds since the Unix epoch; `expires_at` is thirty days later.
    pub issued_at_unix: u64,
}

/// Why a delegation was not minted. Never carries key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintError {
    /// A field failed its shape check; the string names the field.
    InvalidField(&'static str),
    /// The delegation could not be serialized (practically unreachable).
    Serialize(String),
}

impl core::fmt::Display for MintError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidField(field) => write!(f, "invalid {field}"),
            Self::Serialize(e) => write!(f, "delegation serialization failed: {e}"),
        }
    }
}

impl std::error::Error for MintError {}

fn valid_device_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn valid_harness(h: &str) -> bool {
    let b = h.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn valid_label(label: &str) -> bool {
    let n = label.chars().count();
    (1..=MAX_DEVICE_LABEL_CHARS).contains(&n)
        && label.trim() == label
        && !label.chars().any(char::is_control)
}

fn valid_airdress(a: &str) -> bool {
    !a.is_empty()
        && a.len() <= 253
        && !a
            .bytes()
            .any(|b| b == crate::credential::IDENTITY_SEPARATOR || b.is_ascii_whitespace())
}

/// Sign an agent delegation with the root seed.
///
/// `root_seed` is borrowed for the one signature; the signing key built
/// from it is zeroized when it drops. Ed25519 is deterministic, so the
/// same inputs mint byte-identical output — which is what lets a test
/// vector pin the whole object, signature included.
///
/// # Errors
///
/// [`MintError::InvalidField`] naming the first field that failed its
/// shape check (including a device key that is not an Ed25519 point).
pub fn mint_agent_delegation(
    root_seed: &[u8; 32],
    req: &AgentDelegationRequest<'_>,
) -> Result<Map<String, Value>, MintError> {
    if !valid_airdress(req.airdress) {
        return Err(MintError::InvalidField("airdress"));
    }
    if !valid_device_id(req.device_id) {
        return Err(MintError::InvalidField("device_id"));
    }
    if VerifyingKey::from_bytes(&req.device_public_key).is_err() {
        return Err(MintError::InvalidField("device_public_key"));
    }
    if !valid_harness(req.harness) {
        return Err(MintError::InvalidField("harness"));
    }
    if !valid_label(req.device_label) {
        return Err(MintError::InvalidField("device_label"));
    }
    let expires = req
        .issued_at_unix
        .checked_add(AGENT_DELEGATION_LIFETIME_SECS)
        .ok_or(MintError::InvalidField("issued_at"))?;
    let issued_at = crate::credential::format_rfc3339_seconds(req.issued_at_unix)
        .ok_or(MintError::InvalidField("issued_at"))?;
    let expires_at = crate::credential::format_rfc3339_seconds(expires)
        .ok_or(MintError::InvalidField("issued_at"))?;

    let mut obj = Map::new();
    obj.insert("airdress".into(), Value::from(req.airdress));
    obj.insert("device_class".into(), Value::from(AGENT_DEVICE_CLASS));
    obj.insert("device_id".into(), Value::from(req.device_id));
    obj.insert("device_kind".into(), Value::from(AGENT_DEVICE_CLASS));
    obj.insert("device_label".into(), Value::from(req.device_label));
    obj.insert(
        "device_session_public_key".into(),
        Value::from(URL_SAFE_NO_PAD.encode(req.device_public_key)),
    );
    obj.insert("expires_at".into(), Value::from(expires_at));
    obj.insert("harness".into(), Value::from(req.harness));
    obj.insert("issued_at".into(), Value::from(issued_at));
    obj.insert("role".into(), Value::from("human_held"));

    let canonical = crate::canonical::canonical_delegation_bytes(&obj)
        .map_err(|e| MintError::Serialize(e.to_string()))?;
    let mut seed = *root_seed;
    let root = SigningKey::from_bytes(&seed);
    seed.zeroize();
    let signature = root.sign(&canonical);
    drop(root);
    obj.insert(
        "signature".into(),
        Value::from(URL_SAFE_NO_PAD.encode(signature.to_bytes())),
    );
    Ok(obj)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{AirdressIdentity, IdentityVersion};

    /// The `agent-delegation` vector: its `mint` inputs, signed with its
    /// root seed, are the vector's delegation byte for byte.
    fn agent_vector() -> Value {
        let parsed: Value = serde_json::from_str(crate::vectors::DELEGATION).unwrap();
        parsed["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == "agent-delegation")
            .expect("the fixture carries the agent vector")
            .clone()
    }

    fn b64_32(v: &Value) -> [u8; 32] {
        URL_SAFE_NO_PAD
            .decode(v.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn minting_reproduces_the_agent_vector() {
        let v = agent_vector();
        let m = &v["mint"];
        let seed = b64_32(&v["root_seed_b64url"]);
        let req = AgentDelegationRequest {
            airdress: m["airdress"].as_str().unwrap(),
            device_id: m["device_id"].as_str().unwrap(),
            device_public_key: b64_32(&m["device_public_key_b64url"]),
            harness: m["harness"].as_str().unwrap(),
            device_label: m["device_label"].as_str().unwrap(),
            issued_at_unix: m["issued_at_unix"].as_u64().unwrap(),
        };
        let minted = mint_agent_delegation(&seed, &req).unwrap();
        assert_eq!(Value::Object(minted), v["delegation"]);
        assert_eq!(
            SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
            b64_32(&v["root_public_key_b64url"])
        );
    }

    fn request(key: [u8; 32]) -> AgentDelegationRequest<'static> {
        AgentDelegationRequest {
            airdress: "alice.humans.airdress.co",
            device_id: "019f0a1c-3b5d-7e2f-8a41-6c9d0b2e4f17",
            device_public_key: key,
            harness: "claude-code",
            device_label: "Claude Code on build-host",
            issued_at_unix: 1_791_201_600,
        }
    }

    #[test]
    fn the_delegation_is_a_v2_identity_that_verifies_under_the_root_for_thirty_days() {
        let root = SigningKey::from_bytes(&[9; 32]);
        let device = SigningKey::from_bytes(&[3; 32]);
        let req = request(device.verifying_key().to_bytes());
        let d = mint_agent_delegation(&[9; 32], &req).unwrap();
        assert_eq!(d["device_class"], "agent");
        assert_eq!(d["harness"], "claude-code");
        assert_eq!(d["issued_at"], "2026-10-05T12:00:00Z");
        assert_eq!(d["expires_at"], "2026-11-04T12:00:00Z");

        let identity = AirdressIdentity::from_delegation(
            req.airdress.to_owned(),
            root.verifying_key().to_bytes(),
            d,
        );
        assert_eq!(identity.version, IdentityVersion::V2);
        let lookup = |_: &str| Some(root.verifying_key().to_bytes());
        let leaf = device.verifying_key().to_bytes();
        // Valid a second before expiry, refused at it.
        let exp = req.issued_at_unix + AGENT_DELEGATION_LIFETIME_SECS;
        crate::credential::verify_identity_at(&identity, &leaf, &lookup, None, exp - 1)
            .expect("verifies before expiry");
        assert_eq!(
            crate::credential::verify_identity_at(&identity, &leaf, &lookup, None, exp),
            Err(crate::credential::CredentialVerifyError::DelegationExpired)
        );
    }

    #[test]
    fn every_field_is_shape_checked() {
        let key = SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes();
        let cases: [(&str, AgentDelegationRequest<'static>); 7] = [
            (
                "airdress",
                AgentDelegationRequest {
                    airdress: "",
                    ..request(key)
                },
            ),
            (
                "device_id",
                AgentDelegationRequest {
                    device_id: "a b",
                    ..request(key)
                },
            ),
            (
                "harness",
                AgentDelegationRequest {
                    harness: "Claude Code",
                    ..request(key)
                },
            ),
            (
                "device_label",
                AgentDelegationRequest {
                    device_label: " padded",
                    ..request(key)
                },
            ),
            (
                "device_label",
                AgentDelegationRequest {
                    device_label: "",
                    ..request(key)
                },
            ),
            (
                "device_label",
                AgentDelegationRequest {
                    device_label: "bell\u{7}",
                    ..request(key)
                },
            ),
            (
                "issued_at",
                AgentDelegationRequest {
                    issued_at_unix: u64::MAX,
                    ..request(key)
                },
            ),
        ];
        for (field, req) in cases {
            assert_eq!(
                mint_agent_delegation(&[9; 32], &req),
                Err(MintError::InvalidField(field)),
                "{field}"
            );
        }
        // Not a point on the curve.
        let mut bad = [0u8; 32];
        bad[31] = 0x80;
        bad[0] = 2;
        assert!(VerifyingKey::from_bytes(&bad).is_err());
        assert_eq!(
            mint_agent_delegation(&[9; 32], &request(bad)),
            Err(MintError::InvalidField("device_public_key"))
        );
    }
}
