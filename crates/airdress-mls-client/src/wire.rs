//! The operator's envelope shapes, as the phone speaks them.
//!
//! Field names are the wire's, not this crate's: an inbound envelope is
//! the SSE `envelope` event of `GET /v1/chat/envelopes/events`, and an
//! outbound one is the body of `POST /v1/chat/conversations/{id}/envelopes`
//! (the conversation id goes in the path, so it is not serialized).
//! Ciphertext is standard base64 on the wire, both ways.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// What an envelope carries. The operator relays the bytes without
/// reading them; the kind is the one thing it is told in the clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeKind {
    /// An MLS Welcome: someone added this device to a group.
    Welcome,
    /// An MLS application message.
    Application,
    /// An MLS Commit (carries `commit_from_epoch`).
    Commit,
    /// A push-to-talk burst. Not chat; this crate leaves it alone.
    AudioBurst,
    /// A sibling asking to be re-added. Minted by the operator only.
    RejoinRequest,
}

impl EnvelopeKind {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Welcome => "mls_welcome",
            Self::Application => "mls_application",
            Self::Commit => "mls_commit",
            Self::AudioBurst => "audio_burst",
            Self::RejoinRequest => "rejoin_request",
        }
    }

    /// Parse the wire spelling; `None` for a kind this version does not
    /// know, which a caller acknowledges and ignores rather than retries.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "mls_welcome" => Self::Welcome,
            "mls_application" => Self::Application,
            "mls_commit" => Self::Commit,
            "audio_burst" => Self::AudioBurst,
            "rejoin_request" => Self::RejoinRequest,
            _ => return None,
        })
    }
}

mod b64 {
    use super::{Deserialize as _, STANDARD};
    use base64::Engine as _;

    pub(super) fn serialize<S: serde::Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// One envelope received from the operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundEnvelope {
    /// The operator's id for this delivery; what an ack names.
    pub envelope_id: String,
    /// The conversation the operator filed it under, for this recipient.
    ///
    /// Trusted only for a Welcome, which carries no group id. Everything
    /// else is filed by the group it decrypts under.
    pub conversation_id: String,
    /// The wire kind; see [`EnvelopeKind::parse`].
    pub envelope_kind: String,
    /// The sending airdress, from the envelope's cleartext column. Half
    /// of the authenticated data every application message is bound to.
    pub from_airdress: String,
    /// The MLS bytes.
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    /// For a commit: the epoch it was built from.
    #[serde(default)]
    pub commit_from_epoch: Option<i64>,
    /// For an audio burst: its length.
    #[serde(default)]
    pub duration_ms: Option<i32>,
    /// When the operator accepted it (RFC 3339), as the operator wrote it.
    #[serde(default)]
    pub received_at: Option<String>,
}

/// One envelope to post. The conversation id travels in the path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundEnvelope {
    /// The conversation to post it to (path, not body).
    #[serde(skip)]
    pub conversation_id: String,
    /// The wire kind.
    pub envelope_kind: String,
    /// The MLS bytes.
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    /// A fresh UUID per envelope, so a retried POST is one envelope.
    pub idempotency_key: String,
    /// Where it goes, when the conversation does not already say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_airdress: Option<String>,
    /// For a commit: the epoch it was built from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_from_epoch: Option<i64>,
    /// For a commit: [`commit_group_tag`] of its group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_group: Option<String>,
}

impl OutboundEnvelope {
    pub(crate) fn new(conversation_id: &str, kind: EnvelopeKind, ciphertext: Vec<u8>) -> Self {
        Self {
            conversation_id: conversation_id.to_owned(),
            envelope_kind: kind.as_str().to_owned(),
            ciphertext,
            idempotency_key: random_uuid(),
            target_airdress: None,
            commit_from_epoch: None,
            commit_group: None,
        }
    }
}

/// The tag the operator serializes commits by: lowercase hex of the first
/// sixteen bytes of SHA-256 over the group id. Two groups of one
/// conversation then never contend for one epoch slot.
#[must_use]
pub fn commit_group_tag(group_id: &[u8]) -> String {
    let digest = Sha256::digest(group_id);
    digest[..16]
        .iter()
        .fold(String::with_capacity(32), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// What an application message's plaintext holds.
///
/// Devices send the bare block array. The operator's agent sends
/// `{"origin": "agent", "blocks": [...]}` for its own replies and
/// `"sibling"` for copies of another device's words; both forms decode.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LanePayload {
    /// `agent`, `sibling`, or absent for a device's own words.
    pub origin: Option<String>,
    /// The chat blocks, as JSON; this crate does not interpret them.
    pub blocks: serde_json::Value,
}

impl LanePayload {
    /// Decode either form. Anything else is not a chat payload.
    ///
    /// # Errors
    ///
    /// The bytes are not JSON, or are neither an array nor an object with
    /// an array under `blocks`.
    pub fn decode(plaintext: &[u8]) -> Result<Self, String> {
        let value: serde_json::Value =
            serde_json::from_slice(plaintext).map_err(|e| format!("not JSON: {e}"))?;
        match value {
            serde_json::Value::Array(_) => Ok(Self {
                origin: None,
                blocks: value,
            }),
            serde_json::Value::Object(mut obj) => {
                let blocks = obj
                    .remove("blocks")
                    .filter(serde_json::Value::is_array)
                    .ok_or("an object payload carries no `blocks` array")?;
                let origin = match obj.remove("origin") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(serde_json::Value::String(s)) => Some(s),
                    Some(_) => return Err("`origin` is not a string".to_owned()),
                };
                Ok(Self { origin, blocks })
            }
            _ => Err("a payload is a block array or an object with `blocks`".to_owned()),
        }
    }

    /// What a device sends: the bare block array.
    ///
    /// # Errors
    ///
    /// `blocks` is not an array.
    pub fn encode_device(blocks: &serde_json::Value) -> Result<Vec<u8>, String> {
        if !blocks.is_array() {
            return Err("blocks must be an array".to_owned());
        }
        serde_json::to_vec(blocks).map_err(|e| e.to_string())
    }
}

/// A random version-4 UUID, formatted. Enough for an idempotency key.
pub(crate) fn random_uuid() -> String {
    use chacha20poly1305::aead::{OsRng, rand_core::RngCore as _};
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// The group id a message carries in its framing, in the clear (RFC
/// 9420). A Welcome has none.
pub(crate) fn message_group_id(message: &[u8]) -> Option<Vec<u8>> {
    mls_rs::MlsMessage::from_bytes(message)
        .ok()?
        .group_id()
        .map(<[u8]>::to_vec)
}

/// Standard base64, for callers that log or key by a group id.
#[must_use]
pub fn b64_group_id(group_id: &[u8]) -> String {
    STANDARD.encode(group_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbound_parses_the_sse_event_shape() {
        let json = serde_json::json!({
            "envelope_id": "e1", "conversation_id": "c1", "envelope_kind": "mls_application",
            "from_airdress": "a.example", "ciphertext": STANDARD.encode(b"xyz"),
            "commit_from_epoch": null, "duration_ms": null, "received_at": "2026-10-06T00:00:00Z"
        });
        let env: InboundEnvelope = serde_json::from_value(json).unwrap();
        assert_eq!(env.ciphertext, b"xyz");
        assert_eq!(
            EnvelopeKind::parse(&env.envelope_kind),
            Some(EnvelopeKind::Application)
        );
    }

    #[test]
    fn outbound_serializes_the_post_body_without_the_path() {
        let mut env = OutboundEnvelope::new("c1", EnvelopeKind::Commit, b"abc".to_vec());
        env.commit_from_epoch = Some(3);
        env.commit_group = Some("00".repeat(16));
        let v = serde_json::to_value(&env).unwrap();
        assert!(v.get("conversation_id").is_none());
        assert_eq!(v["envelope_kind"], "mls_commit");
        assert_eq!(v["ciphertext"], STANDARD.encode(b"abc"));
        assert!(v.get("target_airdress").is_none());
        assert_eq!(v["idempotency_key"].as_str().unwrap().len(), 36);
    }

    #[test]
    fn every_kind_round_trips() {
        for k in [
            EnvelopeKind::Welcome,
            EnvelopeKind::Application,
            EnvelopeKind::Commit,
            EnvelopeKind::AudioBurst,
            EnvelopeKind::RejoinRequest,
        ] {
            assert_eq!(EnvelopeKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(EnvelopeKind::parse("mls_proposal"), None);
    }
}
