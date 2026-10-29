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
            write!(s, "{b:02x}").expect("formatting into a String is infallible");
            s
        })
}

/// What an application message's plaintext holds.
///
/// Devices used to send the bare block array, and an old device still
/// does. The operator's agent sends `{"origin": "agent", "blocks": [...]}`
/// for its own replies and `"sibling"` for copies of another device's
/// words. A current device sends the object form too, with the message's
/// own reference and, on a reply, what it answers:
/// `{"blocks": [...], "ref": "...", "reply_to": {...}}`. Every form
/// decodes.
///
/// Keys this crate does not know are ignored, at the top level and inside
/// `reply_to`: that is what lets the next field arrive without breaking a
/// decoder already in the field.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LanePayload {
    /// `agent`, `sibling`, or absent for a device's own words.
    pub origin: Option<String>,
    /// The chat blocks, as JSON; this crate does not interpret them.
    pub blocks: serde_json::Value,
    /// The message's own reference, minted by its sender (see
    /// [`mint_message_ref`]). Absent from an old client's messages, and
    /// read as absent when it is not a non-empty string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<String>,
    /// What this message replies to, when it is a reply. A `reply_to`
    /// that is not a well-formed [`ReplyTo`] is read as absent: the
    /// message still decodes, it is just not shown as a reply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<ReplyTo>,
}

/// The message a reply answers, as the replier saw it.
///
/// A receiver finds the original by `(conversation, from, ref)`; `from`
/// is the sending airdress the receiver authenticated, so a sender cannot
/// point a quote at another airdress's message. `snippet` is the
/// replier's assertion of what the original said, to show only when the
/// original itself cannot be found.
///
/// Serializes exactly as it travels: absent optional keys stay absent,
/// never `null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReplyTo {
    /// The original's [`LanePayload::ref`]. Absent when the original
    /// carried none (it came from an old client): a quote-only reply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<String>,
    /// The original's sending airdress.
    pub from: String,
    /// The original's verified agent session name, when the replier had
    /// verified one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by_session: Option<String>,
    /// What the original was: `text`, `code`, `image`, `audio`, `place`,
    /// `live` or `other`. Kept as sent, so a kind added later still
    /// decodes.
    pub kind: String,
    /// Plain text from the original, possibly empty (non-text content).
    pub snippet: String,
}

impl ReplyTo {
    /// Read a `reply_to` object. `None` when it is not one: not an object,
    /// `from` or `kind` missing or not a non-empty string, `snippet` not a
    /// string, or `ref` or `by_session` present and not a string. An empty
    /// `ref` or `by_session` is read as absent. Unknown keys are ignored.
    #[must_use]
    pub fn from_value(value: &serde_json::Value) -> Option<Self> {
        let obj = value.as_object()?;
        let required = |key: &str| {
            obj.get(key)
                .and_then(serde_json::Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        let optional = |key: &str| match obj.get(key) {
            None | Some(serde_json::Value::Null) => Some(None),
            Some(serde_json::Value::String(s)) if s.is_empty() => Some(None),
            Some(serde_json::Value::String(s)) => Some(Some(s.clone())),
            Some(_) => None,
        };
        Some(Self {
            r#ref: optional("ref")?,
            from: required("from")?,
            by_session: optional("by_session")?,
            kind: required("kind")?,
            snippet: obj.get("snippet")?.as_str()?.to_owned(),
        })
    }
}

/// A fresh message reference: sixteen random bytes, base64url without
/// padding (22 characters). Mint it once per message, before the first
/// send attempt, and keep it across retries.
#[must_use]
pub fn mint_message_ref() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chacha20poly1305::aead::{OsRng, rand_core::RngCore as _};
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

impl LanePayload {
    /// Decode any form. Anything else is not a chat payload.
    ///
    /// # Errors
    ///
    /// The bytes are not JSON, or are neither an array nor an object with
    /// an array under `blocks`, or `origin` is present and not a string.
    /// A malformed `ref` or `reply_to` is never an error; it is read as
    /// absent.
    pub fn decode(plaintext: &[u8]) -> Result<Self, String> {
        let value: serde_json::Value =
            serde_json::from_slice(plaintext).map_err(|e| format!("not JSON: {e}"))?;
        match value {
            serde_json::Value::Array(_) => Ok(Self {
                origin: None,
                blocks: value,
                r#ref: None,
                reply_to: None,
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
                let r#ref = match obj.remove("ref") {
                    Some(serde_json::Value::String(s)) if !s.is_empty() => Some(s),
                    _ => None,
                };
                let reply_to = obj.get("reply_to").and_then(ReplyTo::from_value);
                Ok(Self {
                    origin,
                    blocks,
                    r#ref,
                    reply_to,
                })
            }
            _ => Err("a payload is a block array or an object with `blocks`".to_owned()),
        }
    }

    /// The bare block array, as an old device sent it. A current device
    /// sends [`LanePayload::encode_message`] instead, so its messages can
    /// be replied to.
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

    /// What a current device sends: the object form
    /// `{"blocks": [...], "ref": "...", "reply_to": {...}}`, with
    /// `reply_to` only on a reply. An old decoder reads `blocks` and
    /// ignores the rest.
    ///
    /// # Errors
    ///
    /// `blocks` is not an array, or `message_ref` is empty.
    pub fn encode_message(
        blocks: &serde_json::Value,
        message_ref: &str,
        reply_to: Option<&ReplyTo>,
    ) -> Result<Vec<u8>, String> {
        if !blocks.is_array() {
            return Err("blocks must be an array".to_owned());
        }
        if message_ref.is_empty() {
            return Err("a message reference is never empty".to_owned());
        }
        let mut obj = serde_json::Map::new();
        obj.insert("blocks".to_owned(), blocks.clone());
        obj.insert("ref".to_owned(), message_ref.into());
        if let Some(reply_to) = reply_to {
            obj.insert(
                "reply_to".to_owned(),
                serde_json::to_value(reply_to).map_err(|e| e.to_string())?,
            );
        }
        serde_json::to_vec(&obj).map_err(|e| e.to_string())
    }
}

/// A random version-4 UUID, formatted. Enough for an idempotency key.
pub(crate) fn random_uuid() -> String {
    use chacha20poly1305::aead::{OsRng, rand_core::RngCore as _};
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = b.iter().fold(String::with_capacity(32), |mut s, x| {
        use std::fmt::Write as _;
        write!(s, "{x:02x}").expect("formatting into a String is infallible");
        s
    });
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

    fn reply() -> ReplyTo {
        ReplyTo {
            r#ref: Some("Jk2m0PZpQh6Q1wVf3n8sLg".to_owned()),
            from: "b.example".to_owned(),
            by_session: Some("bob".to_owned()),
            kind: "text".to_owned(),
            snippet: "three options".to_owned(),
        }
    }

    #[test]
    fn a_minted_ref_is_sixteen_bytes_base64url_and_fresh() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let a = mint_message_ref();
        let b = mint_message_ref();
        assert_eq!(a.len(), 22);
        assert_eq!(URL_SAFE_NO_PAD.decode(&a).unwrap().len(), 16);
        assert_ne!(a, b);
    }

    #[test]
    fn the_object_form_round_trips_with_ref_and_reply() {
        let blocks = serde_json::json!([{"type": "text", "text": "yes"}]);
        let bytes =
            LanePayload::encode_message(&blocks, "q3v1oV0wQ7i2b9u8h4mYxA", Some(&reply())).unwrap();
        let got = LanePayload::decode(&bytes).unwrap();
        assert_eq!(got.origin, None);
        assert_eq!(got.blocks, blocks);
        assert_eq!(got.r#ref.as_deref(), Some("q3v1oV0wQ7i2b9u8h4mYxA"));
        assert_eq!(got.reply_to, Some(reply()));
        // Keys sort, so the bytes are the same on every encode.
        assert!(bytes.starts_with(br#"{"blocks":"#));
    }

    #[test]
    fn a_plain_message_carries_ref_and_no_reply() {
        let blocks = serde_json::json!([]);
        let bytes = LanePayload::encode_message(&blocks, "r", None).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v, serde_json::json!({"blocks": [], "ref": "r"}));
    }

    #[test]
    fn encode_refuses_what_it_could_not_decode() {
        let blocks = serde_json::json!([]);
        assert!(LanePayload::encode_message(&serde_json::json!({}), "r", None).is_err());
        assert!(LanePayload::encode_message(&blocks, "", None).is_err());
    }

    #[test]
    fn reply_to_serializes_without_nulls() {
        let quote_only = ReplyTo {
            r#ref: None,
            by_session: None,
            ..reply()
        };
        assert_eq!(
            serde_json::to_value(&quote_only).unwrap(),
            serde_json::json!({"from": "b.example", "kind": "text", "snippet": "three options"})
        );
    }

    #[test]
    fn a_malformed_reply_to_is_absent_and_the_message_still_decodes() {
        for bad in [
            serde_json::json!("x"),
            serde_json::json!({"kind": "text", "snippet": ""}),
            serde_json::json!({"from": "", "kind": "text", "snippet": ""}),
            serde_json::json!({"from": "b.example", "snippet": ""}),
            serde_json::json!({"from": "b.example", "kind": "text"}),
            serde_json::json!({"from": "b.example", "kind": "text", "snippet": 3}),
            serde_json::json!({"from": "b.example", "kind": "text", "snippet": "", "ref": 1}),
            serde_json::json!({"from": "b.example", "kind": "text", "snippet": "", "by_session": []}),
        ] {
            let plaintext = serde_json::to_vec(&serde_json::json!({
                "blocks": [], "ref": "r", "reply_to": bad
            }))
            .unwrap();
            let got = LanePayload::decode(&plaintext).unwrap();
            assert_eq!(got.reply_to, None, "{bad}");
            assert_eq!(got.r#ref.as_deref(), Some("r"));
        }
    }

    #[test]
    fn unknown_keys_inside_reply_to_are_ignored() {
        let v = serde_json::json!({
            "from": "b.example", "kind": "sticker", "snippet": "", "ref": "",
            "by_session": null, "colour": "blue"
        });
        let got = ReplyTo::from_value(&v).unwrap();
        assert_eq!(got.r#ref, None);
        assert_eq!(got.by_session, None);
        assert_eq!(got.kind, "sticker");
    }
}
