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

// ---------------------------------------------------------------------------
// Verification (design C4c): the three-part check on every accepted leaf
// ---------------------------------------------------------------------------

/// Why a peer credential was rejected.
///
/// The variants are deliberately distinguishable for client-side
/// telemetry; the user-facing message for all of them is a single
/// string along the lines of "this contact's identity changed".
/// No variant ever carries key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialVerifyError {
    /// Identity bytes did not parse, or the delegation object is
    /// structurally unusable.
    Malformed(String),
    /// Check 1 failed: the delegation signature does not verify over
    /// the canonical delegation bytes with the identity's root key.
    DelegationSignatureInvalid,
    /// Check 2 failed: the root key published by the peer's operator
    /// differs from the identity's root key. HARD reject — this is
    /// the check that makes the delegation an identity chain rather
    /// than a self-assertion.
    RootKeyMismatch,
    /// Check 2 could not run: the host's root-key cache returned
    /// nothing for this airdress. Still a reject — never warn-only.
    RootKeyUnavailable,
    /// Check 3 failed: the delegation's device session key is not the
    /// leaf's MLS signing key (a delegation replayed into another
    /// device's credential).
    SessionKeyMismatch,
    /// A pre-cutover bare-string identity while strict verification
    /// is on.
    LegacyIdentityRejected,
}

impl core::fmt::Display for CredentialVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(msg) => write!(f, "credential malformed: {msg}"),
            Self::DelegationSignatureInvalid => write!(f, "delegation signature invalid"),
            Self::RootKeyMismatch => write!(f, "published root key mismatch"),
            Self::RootKeyUnavailable => write!(f, "published root key unavailable"),
            Self::SessionKeyMismatch => write!(f, "delegation session key mismatch"),
            Self::LegacyIdentityRejected => write!(f, "legacy identity rejected"),
        }
    }
}

impl std::error::Error for CredentialVerifyError {}

impl mls_rs_core::error::IntoAnyError for CredentialVerifyError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

/// Host-supplied source of the root key a peer's operator publishes.
///
/// The FFI crate makes no network calls itself: the host application
/// owns the fetch against the peer operator's root-key endpoint and
/// the 24-hour TTL cache, and exposes both through this lookup.
/// Returning `None` (nothing cached, fetch failed) rejects the leaf —
/// check 2 is never optional or warn-only.
pub trait RootKeyLookup: Send + Sync {
    fn root_public_key(&self, airdress: &str) -> Option<[u8; 32]>;
}

impl<F> RootKeyLookup for F
where
    F: Fn(&str) -> Option<[u8; 32]> + Send + Sync,
{
    fn root_public_key(&self, airdress: &str) -> Option<[u8; 32]> {
        self(airdress)
    }
}

/// Run the three-part chain verification on a parsed v1 identity.
///
/// 1. The delegation signature verifies over the canonical delegation
///    bytes against `identity.root_public_key`.
/// 2. `identity.root_public_key` equals what the peer's operator
///    publishes (via the host's cache). Hard reject on mismatch or
///    unavailability.
/// 3. The delegation's `device_session_public_key` equals the leaf's
///    MLS signing key.
pub fn verify_identity(
    identity: &AirdressIdentity,
    leaf_signing_key: &[u8],
    lookup: &dyn RootKeyLookup,
) -> Result<(), CredentialVerifyError> {
    verify_chain(identity, leaf_signing_key, Some(lookup))
}

/// Checks 1 and 3 always; check 2 when a lookup is present. The
/// lookup-less form exists ONLY for the pre-cutover compat mode of
/// [`AirdressIdentityProvider`] — strict verification always supplies
/// a lookup, and check 2 is then a hard reject in every outcome.
fn verify_chain(
    identity: &AirdressIdentity,
    leaf_signing_key: &[u8],
    lookup: Option<&dyn RootKeyLookup>,
) -> Result<(), CredentialVerifyError> {
    // Check 1 — delegation signature over the canonical bytes.
    let sig_b64 = identity
        .delegation
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| CredentialVerifyError::Malformed("delegation missing signature".into()))?;
    let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| CredentialVerifyError::Malformed("signature base64 invalid".into()))?
        .try_into()
        .map_err(|_| CredentialVerifyError::Malformed("signature is not 64 bytes".into()))?;
    let canonical = crate::canonical::canonical_delegation_bytes(&identity.delegation)
        .map_err(|e| CredentialVerifyError::Malformed(format!("canonicalization failed: {e}")))?;
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&identity.root_public_key)
        .map_err(|_| CredentialVerifyError::Malformed("root public key invalid".into()))?;
    ed25519_dalek::Verifier::verify(
        &verifying,
        &canonical,
        &ed25519_dalek::Signature::from_bytes(&sig_bytes),
    )
    .map_err(|_| CredentialVerifyError::DelegationSignatureInvalid)?;

    // Check 2 — the published root key. This is what turns the
    // delegation from a self-assertion into an identity chain; a miss
    // or a mismatch is a hard reject, never a warning.
    if let Some(lookup) = lookup {
        let published = lookup
            .root_public_key(&identity.airdress)
            .ok_or(CredentialVerifyError::RootKeyUnavailable)?;
        if published != identity.root_public_key {
            return Err(CredentialVerifyError::RootKeyMismatch);
        }
    }

    // Check 3 — the delegation is for THIS leaf's signing key, so a
    // valid delegation for device A cannot be replayed into device
    // B's credential.
    let session_b64 = identity
        .delegation
        .get("device_session_public_key")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CredentialVerifyError::Malformed("delegation missing device_session_public_key".into())
        })?;
    let session_key = URL_SAFE_NO_PAD.decode(session_b64).map_err(|_| {
        CredentialVerifyError::Malformed("device_session_public_key base64 invalid".into())
    })?;
    if session_key != leaf_signing_key {
        return Err(CredentialVerifyError::SessionKeyMismatch);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Identity provider — runs the chain check on every accepted leaf
// ---------------------------------------------------------------------------

/// `mls-rs` identity provider that validates the delegation-carrying
/// credential on every leaf the group accepts.
///
/// Two modes, switched by [`Self::set_root_key_lookup`]:
///
/// - **Compat** (initial): v1 identities get checks 1 and 3 (both
///   purely local); legacy bare-string identities are accepted. This
///   is the pre-cutover state — the host has not yet supplied its
///   root-key cache, and the FFI crate cannot fetch on its own.
/// - **Strict** (after the host registers its root-key lookup): all
///   three checks run, check 2 included, and legacy identities are
///   rejected. Registration is one-way — the cutover flag cannot be
///   unset.
#[derive(Clone, Default)]
pub struct AirdressIdentityProvider {
    lookup: std::sync::Arc<std::sync::RwLock<Option<std::sync::Arc<dyn RootKeyLookup>>>>,
}

impl core::fmt::Debug for AirdressIdentityProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AirdressIdentityProvider")
            .field("strict", &self.is_strict())
            .finish()
    }
}

impl AirdressIdentityProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enter strict mode with the host's root-key cache. One-way.
    pub fn set_root_key_lookup(&self, lookup: std::sync::Arc<dyn RootKeyLookup>) {
        *self.lookup.write().expect("lookup lock poisoned") = Some(lookup);
    }

    pub fn is_strict(&self) -> bool {
        self.lookup.read().expect("lookup lock poisoned").is_some()
    }

    fn validate_leaf(
        &self,
        signing_identity: &mls_rs::identity::SigningIdentity,
    ) -> Result<(), CredentialVerifyError> {
        let basic = signing_identity.credential.as_basic().ok_or_else(|| {
            CredentialVerifyError::Malformed("credential is not a basic credential".into())
        })?;
        let parsed = parse_identity(&basic.identifier).map_err(CredentialVerifyError::Malformed)?;
        let lookup = self.lookup.read().expect("lookup lock poisoned").clone();
        match parsed {
            ParsedIdentity::Legacy(_) => {
                if lookup.is_some() {
                    Err(CredentialVerifyError::LegacyIdentityRejected)
                } else {
                    Ok(())
                }
            }
            ParsedIdentity::V1(identity) => verify_chain(
                &identity,
                signing_identity.signature_key.as_bytes(),
                lookup.as_deref(),
            ),
        }
    }

    fn logical_identity(
        signing_identity: &mls_rs::identity::SigningIdentity,
    ) -> Result<Vec<u8>, CredentialVerifyError> {
        let basic = signing_identity.credential.as_basic().ok_or_else(|| {
            CredentialVerifyError::Malformed("credential is not a basic credential".into())
        })?;
        match parse_identity(&basic.identifier).map_err(CredentialVerifyError::Malformed)? {
            ParsedIdentity::V1(identity) => Ok(identity.airdress.into_bytes()),
            ParsedIdentity::Legacy(airdress) => Ok(airdress.into_bytes()),
        }
    }
}

impl mls_rs::IdentityProvider for AirdressIdentityProvider {
    type Error = CredentialVerifyError;

    fn validate_member(
        &self,
        signing_identity: &mls_rs::identity::SigningIdentity,
        _timestamp: Option<mls_rs::time::MlsTime>,
        _context: mls_rs_core::identity::MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        self.validate_leaf(signing_identity)
    }

    fn validate_external_sender(
        &self,
        signing_identity: &mls_rs::identity::SigningIdentity,
        _timestamp: Option<mls_rs::time::MlsTime>,
        _extensions: Option<&mls_rs::ExtensionList>,
    ) -> Result<(), Self::Error> {
        self.validate_leaf(signing_identity)
    }

    fn identity(
        &self,
        signing_identity: &mls_rs::identity::SigningIdentity,
        _extensions: &mls_rs::ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        // The airdress is the stable member identity: a device that
        // re-enrolls (new delegation, same airdress) stays the same
        // logical member.
        Self::logical_identity(signing_identity)
    }

    fn valid_successor(
        &self,
        predecessor: &mls_rs::identity::SigningIdentity,
        successor: &mls_rs::identity::SigningIdentity,
        _extensions: &mls_rs::ExtensionList,
    ) -> Result<bool, Self::Error> {
        Ok(Self::logical_identity(predecessor)? == Self::logical_identity(successor)?)
    }

    fn supported_types(&self) -> Vec<mls_rs::identity::CredentialType> {
        vec![mls_rs::identity::basic::BasicCredential::credential_type()]
    }
}

/// Shared helpers for tests across the crate: a valid root-signed
/// delegation for a given session key.
#[cfg(test)]
pub(crate) mod test_support {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::{Map, Value};

    /// Build a delegation object for `airdress`/`session_public_key`,
    /// sign it with `root`, and return it as a JSON string.
    pub fn signed_delegation_json(
        root: &SigningKey,
        airdress: &str,
        session_public_key: &[u8; 32],
    ) -> String {
        let mut obj = Map::new();
        obj.insert("airdress".to_owned(), Value::from(airdress));
        obj.insert(
            "device_session_public_key".to_owned(),
            Value::from(URL_SAFE_NO_PAD.encode(session_public_key)),
        );
        obj.insert("device_label".to_owned(), Value::from("test device"));
        obj.insert("role".to_owned(), Value::from("human_held"));
        obj.insert("issued_at".to_owned(), Value::from("2026-01-01T00:00:00Z"));
        let canonical = crate::canonical::canonical_delegation_bytes(&obj).expect("canonicalize");
        let signature = root.sign(&canonical);
        obj.insert(
            "signature".to_owned(),
            Value::from(URL_SAFE_NO_PAD.encode(signature.to_bytes())),
        );
        serde_json::to_string(&Value::Object(obj)).expect("serialize delegation")
    }
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

    // -- verification (three-part chain check) --

    use ed25519_dalek::SigningKey;
    use mls_rs::IdentityProvider as _;
    use mls_rs::identity::SigningIdentity;

    use super::test_support::signed_delegation_json;
    use super::{AirdressIdentityProvider, CredentialVerifyError, verify_identity};

    fn chain_fixture() -> (super::AirdressIdentity, [u8; 32], [u8; 32]) {
        let root = SigningKey::from_bytes(&[11u8; 32]);
        let session = SigningKey::from_bytes(&[22u8; 32]);
        let session_pub = session.verifying_key().to_bytes();
        let delegation_json =
            signed_delegation_json(&root, "alice.humans.airdress.co", &session_pub);
        let delegation: Value = serde_json::from_str(&delegation_json).unwrap();
        let identity = super::AirdressIdentity {
            airdress: "alice.humans.airdress.co".to_owned(),
            root_public_key: root.verifying_key().to_bytes(),
            delegation: delegation.as_object().unwrap().clone(),
        };
        (identity, root.verifying_key().to_bytes(), session_pub)
    }

    #[test]
    fn valid_chain_is_accepted() {
        let (identity, root_pub, session_pub) = chain_fixture();
        let lookup = move |_: &str| Some(root_pub);
        verify_identity(&identity, &session_pub, &lookup).unwrap();
    }

    #[test]
    fn wrong_published_root_is_rejected() {
        let (identity, _, session_pub) = chain_fixture();
        let other_root = SigningKey::from_bytes(&[99u8; 32])
            .verifying_key()
            .to_bytes();
        let lookup = move |_: &str| Some(other_root);
        assert_eq!(
            verify_identity(&identity, &session_pub, &lookup),
            Err(CredentialVerifyError::RootKeyMismatch)
        );
    }

    #[test]
    fn unavailable_published_root_is_rejected() {
        let (identity, _, session_pub) = chain_fixture();
        let lookup = |_: &str| None;
        assert_eq!(
            verify_identity(&identity, &session_pub, &lookup),
            Err(CredentialVerifyError::RootKeyUnavailable)
        );
    }

    #[test]
    fn delegation_for_another_session_key_is_rejected() {
        let (identity, root_pub, _) = chain_fixture();
        let lookup = move |_: &str| Some(root_pub);
        let other_session = SigningKey::from_bytes(&[33u8; 32])
            .verifying_key()
            .to_bytes();
        assert_eq!(
            verify_identity(&identity, &other_session, &lookup),
            Err(CredentialVerifyError::SessionKeyMismatch)
        );
    }

    #[test]
    fn tampered_delegation_signature_is_rejected() {
        let (mut identity, root_pub, session_pub) = chain_fixture();
        identity
            .delegation
            .insert("device_label".to_owned(), json!("tampered"));
        let lookup = move |_: &str| Some(root_pub);
        assert_eq!(
            verify_identity(&identity, &session_pub, &lookup),
            Err(CredentialVerifyError::DelegationSignatureInvalid)
        );
    }

    fn signing_identity_for(identity_bytes: Vec<u8>, session_pub: &[u8; 32]) -> SigningIdentity {
        SigningIdentity::new(
            BasicCredential::new(identity_bytes).into_credential(),
            mls_rs_core::crypto::SignaturePublicKey::from(session_pub.to_vec()),
        )
    }

    #[test]
    fn legacy_identity_rejected_only_in_strict_mode() {
        let provider = AirdressIdentityProvider::new();
        let legacy = signing_identity_for(b"alice.humans.airdress.co".to_vec(), &[0u8; 32]);
        let extensions = mls_rs::ExtensionList::default();

        // Compat: accepted.
        assert!(provider.identity(&legacy, &extensions).is_ok());
        assert!(
            provider
                .validate_external_sender(&legacy, None, None)
                .is_ok()
        );

        // Strict: rejected.
        let (_, root_pub, _) = chain_fixture();
        provider.set_root_key_lookup(std::sync::Arc::new(move |_: &str| Some(root_pub)));
        assert_eq!(
            provider.validate_external_sender(&legacy, None, None),
            Err(CredentialVerifyError::LegacyIdentityRejected)
        );
    }

    #[test]
    fn provider_accepts_valid_v1_leaf_in_strict_mode() {
        let (identity, root_pub, session_pub) = chain_fixture();
        let provider = AirdressIdentityProvider::new();
        provider.set_root_key_lookup(std::sync::Arc::new(move |_: &str| Some(root_pub)));
        let leaf = signing_identity_for(identity.to_identity_bytes().unwrap(), &session_pub);
        assert!(provider.validate_external_sender(&leaf, None, None).is_ok());

        // And the member identity is the airdress, stable across devices.
        assert_eq!(
            provider
                .identity(&leaf, &mls_rs::ExtensionList::default())
                .unwrap(),
            b"alice.humans.airdress.co".to_vec()
        );
    }
}
