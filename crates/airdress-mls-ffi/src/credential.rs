//! Delegation-carrying MLS credential.
//!
//! Per RDR-005 Amendment 1 §10.5 the credential stays a
//! `BasicCredential` — this module only defines what goes INTO its
//! identity bytes: the canonical JSON of
//!
//! ```json
//! { "v": 2,
//!   "airdress": "alice.humans.airdress.co",
//!   "root_public_key": "<b64url 32 bytes>",
//!   "delegation": { ...delegation object, signature included... } }
//! ```
//!
//! serialized with the same canonicalization as delegation signing
//! (`canonical.rs`): compact JSON, object keys sorted at every level.
//!
//! # Two delegation forms (SPEC-061 FR-15, design D-4)
//!
//! The three top-level fields are the same in both versions; what
//! changes is what the delegation object carries.
//!
//! - **`v: 1`** — `airdress`, `device_label`, `device_session_public_key`,
//!   `issued_at`, `role`, `signature`. The member identity is the
//!   bare airdress, so two devices of one airdress collide in
//!   `mls-rs` tree validation. That collision is the entire reason
//!   the `self.local` companion identity exists.
//! - **`v: 2`** — the same, plus `device_id` (stable per physical
//!   device, constant across session-key rotation and re-delegation)
//!   and `expires_at` (RFC 3339). The member identity becomes
//!   `airdress ‖ 0x1F ‖ device_id`, so a multi-leaf group is
//!   representable, and the delegation acquires a named lifetime.
//!
//! Both fields are inside the object the root signs, so adding them
//! is a version break, not an extension.
//!
//! A legacy bare-string identity (a pre-cutover client) still parses,
//! so the loopback harness can exercise both forms. Detection is by
//! "parses as a JSON object with a known `v`", never by heuristics on
//! the first byte.
//!
//! Everything v2 is gated on
//! [`AirdressIdentityProvider::set_v2_cutover`] — one-way, per
//! SPEC-061 NFR-15. Until it is set, `v: 1` keeps validating exactly
//! as before.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};

/// Separator between the airdress and the `device_id` in the member
/// identity bytes (FR-16, design D-4).
///
/// ASCII unit separator: not legal in an airdress FQDN and not legal
/// in a UUID, so `airdress ‖ 0x1F ‖ device_id` is unambiguous. Both
/// components are rejected if they contain it, because "cannot occur"
/// is only true of well-formed inputs and neither component is ours.
pub const IDENTITY_SEPARATOR: u8 = 0x1F;

/// Default delegation lifetime (design D-4): 180 days.
///
/// The minting side owns this; it lives here so the client, the CLI
/// and the agent all mint the same lifetime rather than three.
pub const DEFAULT_DELEGATION_LIFETIME_SECS: u64 = 180 * 24 * 60 * 60;

/// How long before `expires_at` a device should silently re-mint
/// (design D-4): 30 days. The root private key is on the device, so
/// re-minting needs no server, no network and no user action.
pub const DELEGATION_REMINT_WINDOW_SECS: u64 = 30 * 24 * 60 * 60;

/// Which delegation form a structured identity carries.
///
/// The discriminant is the `v` field of the identity bytes, read from
/// the wire — never inferred while parsing. (The *minting* side does
/// infer it from the delegation's fields; see
/// [`AirdressIdentity::from_delegation`], which is a serialization
/// decision about this device's own identity and not a trust
/// decision about a peer's.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityVersion {
    /// Pre-cutover: airdress-scoped member identity, no expiry.
    V1,
    /// SPEC-061: device-scoped member identity, `expires_at` enforced.
    V2,
}

impl IdentityVersion {
    const fn wire_value(self) -> i64 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
        }
    }

    const fn from_wire(v: i64) -> Option<Self> {
        match v {
            1 => Some(Self::V1),
            2 => Some(Self::V2),
            _ => None,
        }
    }
}

/// The structured identity carried in the credential's identity bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AirdressIdentity {
    /// Which delegation form this is. Serialized as `v`.
    pub version: IdentityVersion,
    pub airdress: String,
    pub root_public_key: [u8; 32],
    /// The full delegation object, `signature` field included.
    pub delegation: Map<String, Value>,
}

impl AirdressIdentity {
    /// Build an identity around a delegation this device just minted,
    /// choosing the version from the delegation's own fields: a
    /// delegation carrying both `device_id` and `expires_at` is `v: 2`,
    /// anything else is `v: 1`.
    ///
    /// This is deliberately the ONLY place version is inferred, and it
    /// applies only to identities we mint for ourselves. Inference
    /// keeps the host-facing constructors (`MlsEngine::from_seed`, the
    /// FFI entry points, the agent's self-signed credential) free of a
    /// version argument: whoever signs the delegation decides the
    /// version by deciding what to put in it. Parsing a *peer's*
    /// identity never infers — it reads `v` off the wire.
    #[must_use]
    pub fn from_delegation(
        airdress: String,
        root_public_key: [u8; 32],
        delegation: Map<String, Value>,
    ) -> Self {
        let version =
            if delegation.contains_key("device_id") && delegation.contains_key("expires_at") {
                IdentityVersion::V2
            } else {
                IdentityVersion::V1
            };
        Self {
            version,
            airdress,
            root_public_key,
            delegation,
        }
    }

    /// Serialize to the canonical identity bytes.
    ///
    /// # Errors
    ///
    /// Serialization failure (practically unreachable for values that
    /// were parsed from JSON).
    pub fn to_identity_bytes(&self) -> Result<Vec<u8>, String> {
        let mut obj = Map::new();
        obj.insert("v".to_owned(), Value::from(self.version.wire_value()));
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

    /// The delegation's stable per-device identifier, or `None` when
    /// the delegation does not carry one (every `v: 1` delegation).
    #[must_use]
    pub fn device_id(&self) -> Option<&str> {
        self.delegation.get("device_id").and_then(Value::as_str)
    }

    /// The delegation's RFC 3339 expiry, or `None` when absent.
    #[must_use]
    pub fn expires_at(&self) -> Option<&str> {
        self.delegation.get("expires_at").and_then(Value::as_str)
    }

    /// The member identity `mls-rs` uses to detect duplicate members
    /// (FR-16): `airdress ‖ 0x1F ‖ device_id` for `v: 2`, the bare
    /// airdress for `v: 1`.
    ///
    /// The version decides this, not the presence of `device_id`. A
    /// `v: 1` leaf's member identity must stay exactly what it was, or
    /// every group already on disk stops matching its own members.
    /// Field presence decides the *security* checks instead
    /// (`verify_chain` checks 4 and 5), where the fail-safe direction
    /// is the opposite one.
    ///
    /// # Errors
    ///
    /// [`CredentialVerifyError::MissingDeviceId`] when a `v: 2`
    /// delegation carries no `device_id`;
    /// [`CredentialVerifyError::Malformed`] when either component
    /// contains the separator byte.
    pub fn member_identity(&self) -> Result<Vec<u8>, CredentialVerifyError> {
        if self.airdress.as_bytes().contains(&IDENTITY_SEPARATOR) {
            return Err(CredentialVerifyError::Malformed(
                "airdress contains the identity separator".into(),
            ));
        }
        match self.version {
            IdentityVersion::V1 => Ok(self.airdress.clone().into_bytes()),
            IdentityVersion::V2 => {
                let device_id = self
                    .device_id()
                    .ok_or(CredentialVerifyError::MissingDeviceId)?;
                if device_id.is_empty() {
                    return Err(CredentialVerifyError::MissingDeviceId);
                }
                if device_id.as_bytes().contains(&IDENTITY_SEPARATOR) {
                    return Err(CredentialVerifyError::Malformed(
                        "device_id contains the identity separator".into(),
                    ));
                }
                let mut out = Vec::with_capacity(self.airdress.len() + 1 + device_id.len());
                out.extend_from_slice(self.airdress.as_bytes());
                out.push(IDENTITY_SEPARATOR);
                out.extend_from_slice(device_id.as_bytes());
                Ok(out)
            }
        }
    }
}

/// The identity forms a peer leaf can carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedIdentity {
    /// Delegation-carrying JSON form; [`AirdressIdentity::version`]
    /// says which.
    Structured(AirdressIdentity),
    /// Pre-cutover bare-string identity (the airdress itself).
    Legacy(String),
}

/// Parse credential identity bytes into one of the two forms.
///
/// Rules: bytes that parse as a JSON object with a known `"v"` (1 or
/// 2) are the structured form and must then be fully well-formed (an
/// error, not a fallback, otherwise). Anything else that is valid
/// UTF-8 is a legacy bare-string identity. Invalid UTF-8 is an error.
///
/// An unknown `"v"` is NOT silently treated as legacy — a future
/// version must fail loudly rather than being demoted to a
/// bare-string airdress.
///
/// # Errors
///
/// A structured identity with missing or malformed fields, an
/// unknown version, or bytes that are neither JSON nor UTF-8.
pub fn parse_identity(bytes: &[u8]) -> Result<ParsedIdentity, String> {
    if let Ok(Value::Object(obj)) = serde_json::from_slice::<Value>(bytes)
        && let Some(v) = obj.get("v").and_then(Value::as_i64)
    {
        let version =
            IdentityVersion::from_wire(v).ok_or_else(|| format!("unknown identity version {v}"))?;
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
        return Ok(ParsedIdentity::Structured(AirdressIdentity {
            version,
            airdress,
            root_public_key,
            delegation,
        }));
    }
    let legacy = std::str::from_utf8(bytes)
        .map_err(|_| "identity bytes are neither versioned JSON nor UTF-8".to_owned())?;
    Ok(ParsedIdentity::Legacy(legacy.to_owned()))
}

// ---------------------------------------------------------------------------
// Verification (design C4c + SPEC-061 D-4): the five-part check
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
    /// Check 4 failed (SPEC-061 FR-18): `expires_at` is in the past.
    DelegationExpired,
    /// Check 5 failed (SPEC-061 FR-19): the host's revocation lookup
    /// says this `device_id` is revoked.
    DeviceRevoked,
    /// Check 5 could not run: the host's revocation lookup returned
    /// nothing. A reject, exactly like [`Self::RootKeyUnavailable`] —
    /// a revocation check that warns is not a revocation check.
    RevocationUnavailable,
    /// A `v: 2` identity whose delegation carries no usable
    /// `device_id`. Without it there is no per-device member identity
    /// and no revocation key, so the leaf is unusable.
    MissingDeviceId,
    /// A pre-cutover bare-string identity while strict verification
    /// is on, or a `v: 1` identity after the v2 cutover.
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
            Self::DelegationExpired => write!(f, "delegation expired"),
            Self::DeviceRevoked => write!(f, "device revoked"),
            Self::RevocationUnavailable => write!(f, "device revocation state unavailable"),
            Self::MissingDeviceId => write!(f, "delegation missing device id"),
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

/// What the host knows about a `device_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    /// The device is not revoked.
    Active,
    /// The device's enrollment has been revoked.
    Revoked,
}

/// Host-supplied revocation state for a device (SPEC-061 FR-19).
///
/// Deliberately the same shape as [`RootKeyLookup`]: synchronous,
/// host-owned, `Option`-returning, and `None` is a REJECT
/// ([`CredentialVerifyError::RevocationUnavailable`]) rather than a
/// warning — a revocation check that warns is not a revocation check.
/// The FFI crate fetches nothing; the host answers from the
/// enrollment revocation state it already maintains.
///
/// **This spec builds the socket, not the proof format.** SPEC-050
/// later supplies signed revocation proofs to fill it; until then a
/// host that registers a lookup is asserting its own local view.
///
/// Like [`RootKeyLookup`], check 5 runs only when a lookup has been
/// registered. That is not a softening of the fail-closed posture —
/// it is the same posture check 2 takes, so that a host which has not
/// wired the socket is in the pre-cutover state rather than in a
/// state where nothing validates.
pub trait RevocationLookup: Send + Sync {
    fn device_status(&self, device_id: &str) -> Option<DeviceStatus>;
}

impl<F> RevocationLookup for F
where
    F: Fn(&str) -> Option<DeviceStatus> + Send + Sync,
{
    fn device_status(&self, device_id: &str) -> Option<DeviceStatus> {
        self(device_id)
    }
}

/// Wall-clock source for delegation expiry (SPEC-061 FR-18).
///
/// `mls-rs` passes `Option<MlsTime>` into `validate_member` and
/// `validate_external_sender`, and supplies `None` on several paths.
/// Skipping expiry when the timestamp is absent would make expiry an
/// attacker-selectable option, because the set of paths that pass
/// `None` is not enumerable from our side — so the check always runs,
/// falling back to this clock. It is injected rather than read
/// directly so tests can be deterministic.
pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch.
    fn now_unix_seconds(&self) -> u64;
}

/// Production [`Clock`]: the host's wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_seconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

/// Fixed [`Clock`] for tests and for hosts that carry their own
/// trusted time source.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_unix_seconds(&self) -> u64 {
        self.0
    }
}

/// Run the chain verification on a parsed identity with the system
/// clock and no revocation lookup.
///
/// Retained as the crate's simple entry point (the operator's agent
/// credential tests and any host that has not wired the SPEC-061
/// sockets call it). Checks 4 and 5 still run whenever the delegation
/// itself carries the fields they read.
///
/// # Errors
///
/// Any [`CredentialVerifyError`].
pub fn verify_identity(
    identity: &AirdressIdentity,
    leaf_signing_key: &[u8],
    lookup: &dyn RootKeyLookup,
) -> Result<(), CredentialVerifyError> {
    verify_chain(
        identity,
        leaf_signing_key,
        Some(lookup),
        None,
        SystemClock.now_unix_seconds(),
    )
}

/// [`verify_identity`] with the SPEC-061 sockets supplied explicitly:
/// a revocation lookup (check 5) and an already-resolved wall-clock
/// instant (check 4).
///
/// # Errors
///
/// Any [`CredentialVerifyError`].
pub fn verify_identity_at(
    identity: &AirdressIdentity,
    leaf_signing_key: &[u8],
    lookup: &dyn RootKeyLookup,
    revocation: Option<&dyn RevocationLookup>,
    now_unix_seconds: u64,
) -> Result<(), CredentialVerifyError> {
    verify_chain(
        identity,
        leaf_signing_key,
        Some(lookup),
        revocation,
        now_unix_seconds,
    )
}

/// Checks 1, 3, 4 and 5 always; check 2 when a root lookup is
/// present. The lookup-less form exists ONLY for the pre-cutover
/// compat mode of [`AirdressIdentityProvider`] — strict verification
/// always supplies a lookup, and check 2 is then a hard reject in
/// every outcome.
fn verify_chain(
    identity: &AirdressIdentity,
    leaf_signing_key: &[u8],
    lookup: Option<&dyn RootKeyLookup>,
    revocation: Option<&dyn RevocationLookup>,
    now_unix_seconds: u64,
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

    // Check 4 (FR-18) — expiry. A `v: 2` delegation MUST carry
    // `expires_at`. A `v: 1` delegation normally carries none, but if
    // one is present it is enforced anyway: the field is inside the
    // signed object, so honouring it costs nothing and refusing to
    // honour it would turn "label yourself v1" into a way to keep an
    // expiry field and escape the check.
    match (identity.version, identity.expires_at()) {
        (_, Some(expires_at)) => {
            let expiry = parse_rfc3339_seconds(expires_at).ok_or_else(|| {
                CredentialVerifyError::Malformed("delegation expires_at is not RFC 3339".into())
            })?;
            if expiry <= now_unix_seconds {
                return Err(CredentialVerifyError::DelegationExpired);
            }
        }
        (IdentityVersion::V2, None) => {
            return Err(CredentialVerifyError::Malformed(
                "v2 delegation missing expires_at".into(),
            ));
        }
        (IdentityVersion::V1, None) => {}
    }

    // Check 5 (FR-19) — revocation, keyed on the stable `device_id`.
    // A `v: 2` delegation must carry one; a `v: 1` delegation that
    // happens to carry one is checked too, for the same reason as
    // check 4.
    match (identity.version, identity.device_id()) {
        (_, Some(device_id)) if !device_id.is_empty() => {
            if let Some(revocation) = revocation {
                match revocation.device_status(device_id) {
                    Some(DeviceStatus::Active) => {}
                    Some(DeviceStatus::Revoked) => {
                        return Err(CredentialVerifyError::DeviceRevoked);
                    }
                    None => return Err(CredentialVerifyError::RevocationUnavailable),
                }
            }
        }
        (IdentityVersion::V2, _) => return Err(CredentialVerifyError::MissingDeviceId),
        (IdentityVersion::V1, _) => {}
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// RFC 3339 → Unix seconds
// ---------------------------------------------------------------------------

/// Parse an RFC 3339 timestamp into seconds since the Unix epoch.
///
/// Hand-rolled on purpose. This crate builds as a `cdylib` for four
/// Android ABIs and two iOS targets and keeps its dependency set to
/// the six crates it cannot avoid — the same reason `canonical.rs`
/// duplicates `airdress-common`'s canonicalization rather than
/// depending on it. A date library would be the seventh, for one
/// function.
///
/// Accepts `YYYY-MM-DDThh:mm:ss[.frac](Z|±hh:mm)`, case-insensitive
/// in the `T`/`Z` positions, with a space permitted for `T` (RFC 3339
/// §5.6). Fractional seconds are parsed and discarded — the
/// resolution here is one second, and the client's
/// `DateTime.toIso8601String()` always emits milliseconds.
///
/// Returns `None` for anything else, including timestamps before
/// 1970: a delegation cannot legitimately expire then, and returning
/// a clamped value would silently accept one.
fn parse_rfc3339_seconds(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> {
        let slice = s.get(from..to)?;
        if !slice.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        slice.parse::<i64>().ok()
    };
    if b[4] != b'-' || b[7] != b'-' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    if !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    let year = num(0, 4)?;
    let month = num(5, 7)?;
    let day = num(8, 10)?;
    let hour = num(11, 13)?;
    let minute = num(14, 16)?;
    let second = num(17, 19)?;

    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    // Leap second (:60) is legal in RFC 3339; treat it as :59 rather
    // than rejecting a well-formed timestamp.
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let second = second.min(59);

    // Optional fractional part, then the mandatory offset.
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return None;
        }
    }
    let offset_minutes: i64 = match b.get(i) {
        Some(b'Z' | b'z') if i + 1 == b.len() => 0,
        Some(sign @ (b'+' | b'-')) if i + 6 == b.len() => {
            if b[i + 3] != b':' {
                return None;
            }
            let oh = num(i + 1, i + 3)?;
            let om = num(i + 4, i + 6)?;
            if oh > 23 || om > 59 {
                return None;
            }
            let magnitude = oh * 60 + om;
            if *sign == b'-' { -magnitude } else { magnitude }
        }
        _ => return None,
    };

    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second - offset_minutes * 60;
    u64::try_from(seconds).ok()
}

const fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

const fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 for a proleptic-Gregorian date (Howard
/// Hinnant's `days_from_civil`).
const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

// ---------------------------------------------------------------------------
// Identity provider — runs the chain check on every accepted leaf
// ---------------------------------------------------------------------------

/// `mls-rs` identity provider that validates the delegation-carrying
/// credential on every leaf the group accepts.
///
/// Two independent one-way switches:
///
/// - [`Self::set_root_key_lookup`] — **strict mode**. Before it, `v: 1`
///   identities get checks 1 and 3 (both purely local) and legacy
///   bare-string identities are accepted; the host has not yet
///   supplied its root-key cache and this crate cannot fetch on its
///   own. After it, check 2 runs and legacy identities are rejected.
/// - [`Self::set_v2_cutover`] — **the SPEC-061 cutover** (FR-20,
///   NFR-15). After it, `v: 1` identities are rejected too, and the
///   per-device member identity is the only form in the tree.
///
/// The two are separate because they answer different questions
/// ("does the host have a root-key cache yet?" versus "has this
/// deployment moved to the v2 wire?"), and because strict mode
/// already shipped. They are not four flags: within v2, the credential
/// form, the AAD binding, multi-leaf formation and group abandonment
/// all move together on this single switch.
///
/// Both are one-way within a process. There is no unset.
#[derive(Clone)]
pub struct AirdressIdentityProvider {
    lookup: std::sync::Arc<std::sync::RwLock<Option<std::sync::Arc<dyn RootKeyLookup>>>>,
    revocation: std::sync::Arc<std::sync::RwLock<Option<std::sync::Arc<dyn RevocationLookup>>>>,
    clock: std::sync::Arc<std::sync::RwLock<std::sync::Arc<dyn Clock>>>,
    v2_cutover: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Default for AirdressIdentityProvider {
    fn default() -> Self {
        Self {
            lookup: std::sync::Arc::new(std::sync::RwLock::new(None)),
            revocation: std::sync::Arc::new(std::sync::RwLock::new(None)),
            clock: std::sync::Arc::new(std::sync::RwLock::new(std::sync::Arc::new(SystemClock))),
            v2_cutover: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
}

impl core::fmt::Debug for AirdressIdentityProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AirdressIdentityProvider")
            .field("strict", &self.is_strict())
            .field("v2_cutover", &self.is_v2_cutover())
            .finish()
    }
}

impl AirdressIdentityProvider {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enter strict mode with the host's root-key cache. One-way.
    ///
    /// # Panics
    ///
    /// If the lookup lock is poisoned — unrecoverable.
    pub fn set_root_key_lookup(&self, lookup: std::sync::Arc<dyn RootKeyLookup>) {
        *self.lookup.write().expect("lookup lock poisoned") = Some(lookup);
    }

    /// Register the host's device-revocation state (check 5, FR-19).
    ///
    /// # Panics
    ///
    /// If the revocation lock is poisoned — unrecoverable.
    pub fn set_revocation_lookup(&self, revocation: std::sync::Arc<dyn RevocationLookup>) {
        *self.revocation.write().expect("revocation lock poisoned") = Some(revocation);
    }

    /// Replace the wall clock used for check 4 when `mls-rs` supplies
    /// no timestamp. Production leaves this as [`SystemClock`]; tests
    /// and hosts with their own trusted time source set it at
    /// construction.
    ///
    /// # Panics
    ///
    /// If the clock lock is poisoned — unrecoverable.
    pub fn set_clock(&self, clock: std::sync::Arc<dyn Clock>) {
        *self.clock.write().expect("clock lock poisoned") = clock;
    }

    /// Enter the SPEC-061 v2 cutover: `v: 1` identities stop being
    /// accepted (FR-20). One-way, per NFR-15 — a reversible cutover
    /// is a four-state matrix nobody tests.
    pub fn set_v2_cutover(&self) {
        self.v2_cutover
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// # Panics
    ///
    /// If the lookup lock is poisoned — unrecoverable.
    #[must_use]
    pub fn is_strict(&self) -> bool {
        self.lookup.read().expect("lookup lock poisoned").is_some()
    }

    #[must_use]
    pub fn is_v2_cutover(&self) -> bool {
        self.v2_cutover.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// # Panics
    ///
    /// If the clock lock is poisoned — unrecoverable.
    fn now(&self, timestamp: Option<mls_rs::time::MlsTime>) -> u64 {
        timestamp.map_or_else(
            || {
                self.clock
                    .read()
                    .expect("clock lock poisoned")
                    .now_unix_seconds()
            },
            |t| t.seconds_since_epoch(),
        )
    }

    /// Run checks 1 and 3-5 against an explicitly supplied root-key
    /// lookup (check 2), using this provider's revocation lookup and
    /// clock.
    ///
    /// The operator's agent resolves the published root per-call from
    /// its own pin table rather than from a cache registered here, so
    /// it needs to hand check 2 in while inheriting everything else.
    /// Sharing this entry point is what keeps the two providers in
    /// lockstep: an expiry or revocation rule added here reaches the
    /// agent without being written twice.
    ///
    /// # Errors
    ///
    /// Any [`CredentialVerifyError`].
    ///
    /// # Panics
    ///
    /// If the revocation lock is poisoned — unrecoverable.
    pub fn verify_with_root_lookup(
        &self,
        identity: &AirdressIdentity,
        leaf_signing_key: &[u8],
        lookup: &dyn RootKeyLookup,
        timestamp: Option<mls_rs::time::MlsTime>,
    ) -> Result<(), CredentialVerifyError> {
        let revocation = self
            .revocation
            .read()
            .expect("revocation lock poisoned")
            .clone();
        verify_chain(
            identity,
            leaf_signing_key,
            Some(lookup),
            revocation.as_deref(),
            self.now(timestamp),
        )
    }

    /// Reject a form the v2 cutover retired: a legacy bare string, or
    /// a `v: 1` identity (FR-20).
    ///
    /// Applied on every path that reads a credential, `identity` and
    /// `valid_successor` included, because after the cutover those
    /// forms do not exist rather than merely failing validation.
    ///
    /// Strict mode's separate rejection of legacy identities is NOT
    /// folded in here. That one is scoped to `validate_leaf` exactly
    /// as it shipped: widening it to `identity` would change how a
    /// group formed before strict mode was armed behaves on load,
    /// which is a different question from this cutover.
    fn reject_cutover_retired_form(
        &self,
        parsed: &ParsedIdentity,
    ) -> Result<(), CredentialVerifyError> {
        if !self.is_v2_cutover() {
            return Ok(());
        }
        match parsed {
            ParsedIdentity::Legacy(_) => Err(CredentialVerifyError::LegacyIdentityRejected),
            ParsedIdentity::Structured(identity) if identity.version == IdentityVersion::V1 => {
                Err(CredentialVerifyError::LegacyIdentityRejected)
            }
            ParsedIdentity::Structured(_) => Ok(()),
        }
    }

    fn validate_leaf(
        &self,
        signing_identity: &mls_rs::identity::SigningIdentity,
        timestamp: Option<mls_rs::time::MlsTime>,
    ) -> Result<(), CredentialVerifyError> {
        let basic = signing_identity.credential.as_basic().ok_or_else(|| {
            CredentialVerifyError::Malformed("credential is not a basic credential".into())
        })?;
        let parsed = parse_identity(&basic.identifier).map_err(CredentialVerifyError::Malformed)?;
        self.reject_cutover_retired_form(&parsed)?;
        let lookup = self.lookup.read().expect("lookup lock poisoned").clone();
        let revocation = self
            .revocation
            .read()
            .expect("revocation lock poisoned")
            .clone();
        match parsed {
            // Strict mode retires the bare-string form on its own,
            // ahead of and independent of the v2 cutover.
            ParsedIdentity::Legacy(_) => {
                if lookup.is_some() {
                    Err(CredentialVerifyError::LegacyIdentityRejected)
                } else {
                    Ok(())
                }
            }
            ParsedIdentity::Structured(identity) => verify_chain(
                &identity,
                signing_identity.signature_key.as_bytes(),
                lookup.as_deref(),
                revocation.as_deref(),
                self.now(timestamp),
            ),
        }
    }

    /// The bytes `mls-rs` uses to detect duplicate members, plus the
    /// root this leaf chains to.
    ///
    /// The pair is computed together because [`valid_successor`](mls_rs::IdentityProvider::valid_successor)
    /// needs both and must not be able to compare one while forgetting
    /// the other. `None` for the root means a legacy bare-string
    /// identity, which chains to nothing.
    fn member_facts(
        &self,
        signing_identity: &mls_rs::identity::SigningIdentity,
    ) -> Result<(Vec<u8>, Option<[u8; 32]>), CredentialVerifyError> {
        let basic = signing_identity.credential.as_basic().ok_or_else(|| {
            CredentialVerifyError::Malformed("credential is not a basic credential".into())
        })?;
        let parsed = parse_identity(&basic.identifier).map_err(CredentialVerifyError::Malformed)?;
        self.reject_cutover_retired_form(&parsed)?;
        match parsed {
            ParsedIdentity::Structured(identity) => {
                let root = identity.root_public_key;
                Ok((identity.member_identity()?, Some(root)))
            }
            ParsedIdentity::Legacy(airdress) => Ok((airdress.into_bytes(), None)),
        }
    }
}

impl mls_rs::IdentityProvider for AirdressIdentityProvider {
    type Error = CredentialVerifyError;

    fn validate_member(
        &self,
        signing_identity: &mls_rs::identity::SigningIdentity,
        timestamp: Option<mls_rs::time::MlsTime>,
        _context: mls_rs_core::identity::MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        self.validate_leaf(signing_identity, timestamp)
    }

    fn validate_external_sender(
        &self,
        signing_identity: &mls_rs::identity::SigningIdentity,
        timestamp: Option<mls_rs::time::MlsTime>,
        _extensions: Option<&mls_rs::ExtensionList>,
    ) -> Result<(), Self::Error> {
        self.validate_leaf(signing_identity, timestamp)
    }

    /// The member identity `mls-rs` uses to detect duplicate members.
    ///
    /// `v: 2` returns `airdress ‖ 0x1F ‖ device_id` (FR-16), so two
    /// devices of one airdress are two distinct members and a group
    /// can hold one leaf per device. `v: 1` returns the bare airdress,
    /// which is precisely why it cannot: two `v: 1` leaves of one
    /// airdress collide in tree validation, and that collision is the
    /// entire reason the `self.local` companion identity exists.
    ///
    /// The identity is NOT derived from the session public key. It
    /// rotates, and [`valid_successor`](mls_rs::IdentityProvider::valid_successor) exists so that a device
    /// which re-delegates with a new session key stays the same
    /// member.
    fn identity(
        &self,
        signing_identity: &mls_rs::identity::SigningIdentity,
        _extensions: &mls_rs::ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(self.member_facts(signing_identity)?.0)
    }

    /// Whether `successor` may take over `predecessor`'s leaf.
    ///
    /// Three checks, all of which must hold (design D-4):
    ///
    /// 1. **same airdress** — as before;
    /// 2. **same `device_id`** — new, and it closes a real hole. With
    ///    the airdress as the member identity, device B's credential
    ///    was a valid successor to device A's leaf: a silent leaf
    ///    takeover inside one airdress, needing no key compromise.
    ///    It was unreachable only because there has never been more
    ///    than one leaf per airdress, and multi-leaf makes it
    ///    reachable, so it is fixed in the same edit rather than left
    ///    as a multi-leaf inconvenience;
    /// 3. **same `root_public_key`** — new, and it matters for
    ///    SPEC-060: after a root recovery, leaves under the old root
    ///    must not be silently succeeded by leaves under the new one.
    ///    The peer's TOFU pin is the user-facing half of that; this is
    ///    the tree-validation half.
    ///
    /// Checks 1 and 2 are both carried by the identity bytes, so they
    /// are one comparison: for `v: 2` that value already includes the
    /// `device_id`, and a `v: 1` predecessor can never match a `v: 2`
    /// successor because the encodings differ.
    fn valid_successor(
        &self,
        predecessor: &mls_rs::identity::SigningIdentity,
        successor: &mls_rs::identity::SigningIdentity,
        _extensions: &mls_rs::ExtensionList,
    ) -> Result<bool, Self::Error> {
        Ok(self.member_facts(predecessor)? == self.member_facts(successor)?)
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

    /// Sign `obj` with `root` and return it with the signature added,
    /// as a JSON string.
    fn sign(root: &SigningKey, mut obj: Map<String, Value>) -> String {
        let canonical = crate::canonical::canonical_delegation_bytes(&obj).expect("canonicalize");
        let signature = root.sign(&canonical);
        obj.insert(
            "signature".to_owned(),
            Value::from(URL_SAFE_NO_PAD.encode(signature.to_bytes())),
        );
        serde_json::to_string(&Value::Object(obj)).expect("serialize delegation")
    }

    fn base(airdress: &str, session_public_key: &[u8; 32]) -> Map<String, Value> {
        let mut obj = Map::new();
        obj.insert("airdress".to_owned(), Value::from(airdress));
        obj.insert(
            "device_session_public_key".to_owned(),
            Value::from(URL_SAFE_NO_PAD.encode(session_public_key)),
        );
        obj.insert("device_label".to_owned(), Value::from("test device"));
        obj.insert("role".to_owned(), Value::from("human_held"));
        obj.insert("issued_at".to_owned(), Value::from("2026-01-01T00:00:00Z"));
        obj
    }

    /// Build a `v: 1` delegation object for
    /// `airdress`/`session_public_key`, sign it with `root`, and
    /// return it as a JSON string.
    pub fn signed_delegation_json(
        root: &SigningKey,
        airdress: &str,
        session_public_key: &[u8; 32],
    ) -> String {
        sign(root, base(airdress, session_public_key))
    }

    /// The `v: 2` form: the same object plus `device_id` and
    /// `expires_at` (SPEC-061 FR-15).
    pub fn signed_delegation_json_v2(
        root: &SigningKey,
        airdress: &str,
        session_public_key: &[u8; 32],
        device_id: &str,
        expires_at: &str,
    ) -> String {
        let mut obj = base(airdress, session_public_key);
        obj.insert("device_id".to_owned(), Value::from(device_id));
        obj.insert("expires_at".to_owned(), Value::from(expires_at));
        sign(root, obj)
    }
}

#[cfg(test)]
mod tests {
    use mls_rs::identity::basic::BasicCredential;
    use serde_json::{Value, json};

    use super::{AirdressIdentity, IdentityVersion, ParsedIdentity, parse_identity};

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
            version: IdentityVersion::V1,
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

    /// The `v: 2` vector in the shared cross-crate fixture — the one
    /// that carries `device_id` and `expires_at`. Both crates
    /// canonicalize it and both must produce the same bytes.
    fn fixture_identity_v2() -> AirdressIdentity {
        let parsed: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../airdress-common/tests/fixtures/delegation_vectors.json"
        )))
        .unwrap();
        let vector = parsed["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == json!("spec-061-v2-delegation"))
            .expect("fixture carries the v2 vector");
        AirdressIdentity {
            version: IdentityVersion::V2,
            airdress: vector["delegation"]["airdress"]
                .as_str()
                .unwrap()
                .to_owned(),
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
            ParsedIdentity::Structured(back) => assert_eq!(back, identity),
            ParsedIdentity::Legacy(_) => panic!("v1 identity parsed as legacy"),
        }
    }

    #[test]
    fn v2_identity_bytes_round_trip() {
        let identity = fixture_identity_v2();
        let bytes = identity.to_identity_bytes().unwrap();
        let as_value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(as_value["v"], json!(2));

        match parse_identity(&bytes).unwrap() {
            ParsedIdentity::Structured(back) => {
                assert_eq!(back, identity);
                assert_eq!(back.version, IdentityVersion::V2);
                assert!(back.device_id().is_some());
                assert!(back.expires_at().is_some());
            }
            ParsedIdentity::Legacy(_) => panic!("v2 identity parsed as legacy"),
        }
    }

    #[test]
    fn version_is_inferred_from_the_delegations_own_fields() {
        let v1 = fixture_identity();
        let inferred_v1 = AirdressIdentity::from_delegation(
            v1.airdress.clone(),
            v1.root_public_key,
            v1.delegation.clone(),
        );
        assert_eq!(inferred_v1.version, IdentityVersion::V1);

        let v2 = fixture_identity_v2();
        let inferred_v2 = AirdressIdentity::from_delegation(
            v2.airdress.clone(),
            v2.root_public_key,
            v2.delegation.clone(),
        );
        assert_eq!(inferred_v2.version, IdentityVersion::V2);
    }

    #[test]
    fn identity_round_trips_through_mls_credential() {
        let identity = fixture_identity();
        let bytes = identity.to_identity_bytes().unwrap();
        let credential = BasicCredential::new(bytes.clone()).into_credential();
        let basic = credential.as_basic().expect("still a BasicCredential");
        assert_eq!(basic.identifier, bytes);
        match parse_identity(&basic.identifier).unwrap() {
            ParsedIdentity::Structured(back) => assert_eq!(back, identity),
            ParsedIdentity::Legacy(_) => panic!("v1 identity parsed as legacy"),
        }
    }

    #[test]
    fn legacy_bare_string_still_parses() {
        match parse_identity(b"alice.humans.airdress.co").unwrap() {
            ParsedIdentity::Legacy(s) => assert_eq!(s, "alice.humans.airdress.co"),
            ParsedIdentity::Structured(_) => panic!("bare string parsed as structured"),
        }
    }

    #[test]
    fn json_object_without_a_version_is_legacy() {
        // Detection is "JSON object with a known v", so an object
        // without one falls through to the legacy branch (it is valid
        // UTF-8).
        let bytes = br#"{"airdress":"alice.test"}"#;
        match parse_identity(bytes).unwrap() {
            ParsedIdentity::Legacy(s) => assert_eq!(s.as_bytes(), bytes),
            ParsedIdentity::Structured(_) => panic!("object without v must not be structured"),
        }
    }

    #[test]
    fn unknown_version_is_an_error_not_a_silent_downgrade() {
        // A future v:3 must fail loudly rather than be demoted to a
        // bare-string airdress, which would drop every check.
        let bytes = br#"{"v":3,"airdress":"alice.test","root_public_key":"","delegation":{}}"#;
        assert!(parse_identity(bytes).is_err());
    }

    #[test]
    fn versioned_object_with_bad_fields_is_an_error_not_legacy() {
        assert!(parse_identity(br#"{"v":1,"airdress":"alice.test"}"#).is_err());
        assert!(parse_identity(br#"{"v":2,"airdress":"alice.test"}"#).is_err());
    }

    #[test]
    fn invalid_utf8_is_an_error() {
        assert!(parse_identity(&[0xff, 0xfe, 0x01]).is_err());
    }

    // -- RFC 3339 parsing (check 4's input) --

    use super::parse_rfc3339_seconds;

    #[test]
    fn rfc3339_parses_the_forms_our_clients_emit() {
        // Epoch, and a known instant: 2026-09-05T12:00:00Z.
        assert_eq!(parse_rfc3339_seconds("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_seconds("2026-09-05T12:00:00Z"),
            Some(1_788_609_600)
        );
        // Dart's DateTime.toIso8601String() always emits millis.
        assert_eq!(
            parse_rfc3339_seconds("2026-09-05T12:00:00.000Z"),
            Some(1_788_609_600)
        );
        // chrono's to_rfc3339() emits a numeric offset.
        assert_eq!(
            parse_rfc3339_seconds("2026-09-05T14:00:00+02:00"),
            Some(1_788_609_600)
        );
        assert_eq!(
            parse_rfc3339_seconds("2026-09-05T10:00:00-02:00"),
            Some(1_788_609_600)
        );
        // Lowercase separators are legal (RFC 3339 §5.6).
        assert_eq!(
            parse_rfc3339_seconds("2026-09-05t12:00:00z"),
            Some(1_788_609_600)
        );
        // Leap day.
        assert_eq!(
            parse_rfc3339_seconds("2024-02-29T00:00:00Z"),
            Some(1_709_164_800)
        );
    }

    #[test]
    fn rfc3339_rejects_what_it_cannot_read() {
        for bad in [
            "",
            "2026-09-05",
            "2026-09-05T12:00:00",      // no offset
            "2026-13-01T00:00:00Z",     // month 13
            "2023-02-29T00:00:00Z",     // not a leap year
            "2026-09-05T24:00:00Z",     // hour 24
            "2026-09-05T12:60:00Z",     // minute 60
            "2026-09-05T12:00:00.Z",    // empty fraction
            "2026-09-05T12:00:00+0200", // offset without a colon
            "1969-12-31T23:59:59Z",     // before the epoch
            "20260905T120000Z",         // basic format
        ] {
            assert_eq!(parse_rfc3339_seconds(bad), None, "must reject {bad:?}");
        }
    }

    // -- verification (the five-part chain check) --

    use ed25519_dalek::SigningKey;
    use mls_rs::IdentityProvider as _;
    use mls_rs::identity::SigningIdentity;

    use super::test_support::{signed_delegation_json, signed_delegation_json_v2};
    use super::{
        AirdressIdentityProvider, CredentialVerifyError, DeviceStatus, FixedClock,
        IDENTITY_SEPARATOR, verify_identity, verify_identity_at,
    };

    const FAR_FUTURE: &str = "2099-01-01T00:00:00Z";
    /// 2026-09-05T12:00:00Z — "now" for every clock-dependent test.
    const NOW: u64 = 1_788_609_600;

    fn chain_fixture() -> (AirdressIdentity, [u8; 32], [u8; 32]) {
        let root = SigningKey::from_bytes(&[11u8; 32]);
        let session = SigningKey::from_bytes(&[22u8; 32]);
        let session_pub = session.verifying_key().to_bytes();
        let delegation_json =
            signed_delegation_json(&root, "alice.humans.airdress.co", &session_pub);
        let delegation: Value = serde_json::from_str(&delegation_json).unwrap();
        let identity = AirdressIdentity {
            version: IdentityVersion::V1,
            airdress: "alice.humans.airdress.co".to_owned(),
            root_public_key: root.verifying_key().to_bytes(),
            delegation: delegation.as_object().unwrap().clone(),
        };
        (identity, root.verifying_key().to_bytes(), session_pub)
    }

    /// A `v: 2` identity for one device: `(identity, session_pub)`.
    fn v2_identity(
        root: &SigningKey,
        airdress: &str,
        session_seed: u8,
        device_id: &str,
        expires_at: &str,
    ) -> (AirdressIdentity, [u8; 32]) {
        let session = SigningKey::from_bytes(&[session_seed; 32]);
        let session_pub = session.verifying_key().to_bytes();
        let json = signed_delegation_json_v2(root, airdress, &session_pub, device_id, expires_at);
        let delegation: Value = serde_json::from_str(&json).unwrap();
        (
            AirdressIdentity {
                version: IdentityVersion::V2,
                airdress: airdress.to_owned(),
                root_public_key: root.verifying_key().to_bytes(),
                delegation: delegation.as_object().unwrap().clone(),
            },
            session_pub,
        )
    }

    fn signing_identity_for(identity_bytes: Vec<u8>, session_pub: &[u8; 32]) -> SigningIdentity {
        SigningIdentity::new(
            BasicCredential::new(identity_bytes).into_credential(),
            mls_rs_core::crypto::SignaturePublicKey::from(session_pub.to_vec()),
        )
    }

    fn leaf_for(identity: &AirdressIdentity, session_pub: &[u8; 32]) -> SigningIdentity {
        signing_identity_for(identity.to_identity_bytes().unwrap(), session_pub)
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

    // -- FR-16: the member identity is per-device --

    #[test]
    fn spec_061_two_devices_of_one_airdress_get_different_identities() {
        // The hinge of the whole spec: with the airdress as the member
        // identity these two collide in mls-rs tree validation, and a
        // multi-leaf group is unrepresentable.
        let root = SigningKey::from_bytes(&[11u8; 32]);
        let (phone, phone_pub) = v2_identity(
            &root,
            "alice.humans.airdress.co",
            22,
            "device-phone",
            FAR_FUTURE,
        );
        let (laptop, laptop_pub) = v2_identity(
            &root,
            "alice.humans.airdress.co",
            33,
            "device-laptop",
            FAR_FUTURE,
        );

        let provider = AirdressIdentityProvider::new();
        let extensions = mls_rs::ExtensionList::default();
        let phone_id = provider
            .identity(&leaf_for(&phone, &phone_pub), &extensions)
            .unwrap();
        let laptop_id = provider
            .identity(&leaf_for(&laptop, &laptop_pub), &extensions)
            .unwrap();

        assert_ne!(phone_id, laptop_id);
        let mut expected = b"alice.humans.airdress.co".to_vec();
        expected.push(IDENTITY_SEPARATOR);
        expected.extend_from_slice(b"device-phone");
        assert_eq!(phone_id, expected);
    }

    #[test]
    fn spec_061_v1_identity_is_still_the_bare_airdress() {
        let (identity, _, session_pub) = chain_fixture();
        let provider = AirdressIdentityProvider::new();
        assert_eq!(
            provider
                .identity(
                    &leaf_for(&identity, &session_pub),
                    &mls_rs::ExtensionList::default()
                )
                .unwrap(),
            b"alice.humans.airdress.co".to_vec()
        );
    }

    #[test]
    fn spec_061_a_separator_byte_in_either_component_is_refused() {
        let root = SigningKey::from_bytes(&[11u8; 32]);
        let (sneaky, sneaky_pub) = v2_identity(
            &root,
            "alice.humans.airdress.co",
            22,
            "device\u{1f}laptop",
            FAR_FUTURE,
        );
        let provider = AirdressIdentityProvider::new();
        assert!(matches!(
            provider.identity(
                &leaf_for(&sneaky, &sneaky_pub),
                &mls_rs::ExtensionList::default()
            ),
            Err(CredentialVerifyError::Malformed(_))
        ));
    }

    #[test]
    fn spec_061_v2_without_a_device_id_is_refused() {
        let root = SigningKey::from_bytes(&[11u8; 32]);
        let (mut identity, session_pub) = v2_identity(
            &root,
            "alice.humans.airdress.co",
            22,
            "device-phone",
            FAR_FUTURE,
        );
        identity.delegation.remove("device_id");
        let provider = AirdressIdentityProvider::new();
        assert_eq!(
            provider.identity(
                &leaf_for(&identity, &session_pub),
                &mls_rs::ExtensionList::default()
            ),
            Err(CredentialVerifyError::MissingDeviceId)
        );
    }

    // -- FR-17: valid_successor --

    #[test]
    fn spec_061_a_sibling_device_is_not_a_valid_successor() {
        // THE HOLE. Before this change `valid_successor` compared
        // airdresses, so device B's credential succeeded device A's
        // leaf: a silent leaf takeover inside one airdress, needing no
        // key compromise at all.
        let root = SigningKey::from_bytes(&[11u8; 32]);
        let (phone, phone_pub) = v2_identity(
            &root,
            "alice.humans.airdress.co",
            22,
            "device-phone",
            FAR_FUTURE,
        );
        let (laptop, laptop_pub) = v2_identity(
            &root,
            "alice.humans.airdress.co",
            33,
            "device-laptop",
            FAR_FUTURE,
        );

        let provider = AirdressIdentityProvider::new();
        assert!(
            !provider
                .valid_successor(
                    &leaf_for(&phone, &phone_pub),
                    &leaf_for(&laptop, &laptop_pub),
                    &mls_rs::ExtensionList::default()
                )
                .unwrap(),
            "a sibling device must never succeed another device's leaf"
        );
    }

    #[test]
    fn spec_061_a_re_delegated_device_keeps_its_leaf() {
        // Same device, new session key, re-signed delegation: still
        // the same member. This is what forbids deriving the identity
        // from the session public key.
        let root = SigningKey::from_bytes(&[11u8; 32]);
        let (before, before_pub) = v2_identity(
            &root,
            "alice.humans.airdress.co",
            22,
            "device-phone",
            FAR_FUTURE,
        );
        let (after, after_pub) = v2_identity(
            &root,
            "alice.humans.airdress.co",
            44,
            "device-phone",
            "2098-01-01T00:00:00Z",
        );
        assert_ne!(before_pub, after_pub, "the session key must have rotated");

        let provider = AirdressIdentityProvider::new();
        assert!(
            provider
                .valid_successor(
                    &leaf_for(&before, &before_pub),
                    &leaf_for(&after, &after_pub),
                    &mls_rs::ExtensionList::default()
                )
                .unwrap()
        );
    }

    #[test]
    fn spec_061_the_same_device_under_a_different_root_is_not_a_successor() {
        // SPEC-060: after a root recovery, leaves under the old root
        // must not be silently succeeded by leaves under the new one.
        let old_root = SigningKey::from_bytes(&[11u8; 32]);
        let new_root = SigningKey::from_bytes(&[77u8; 32]);
        let (before, before_pub) = v2_identity(
            &old_root,
            "alice.humans.airdress.co",
            22,
            "device-phone",
            FAR_FUTURE,
        );
        let (after, after_pub) = v2_identity(
            &new_root,
            "alice.humans.airdress.co",
            22,
            "device-phone",
            FAR_FUTURE,
        );

        let provider = AirdressIdentityProvider::new();
        assert!(
            !provider
                .valid_successor(
                    &leaf_for(&before, &before_pub),
                    &leaf_for(&after, &after_pub),
                    &mls_rs::ExtensionList::default()
                )
                .unwrap()
        );
    }

    #[test]
    fn spec_061_a_v1_leaf_cannot_be_succeeded_by_a_v2_leaf() {
        let root = SigningKey::from_bytes(&[11u8; 32]);
        let (v1, _, v1_pub) = chain_fixture();
        let (v2, v2_pub) = v2_identity(
            &root,
            "alice.humans.airdress.co",
            22,
            "device-phone",
            FAR_FUTURE,
        );

        let provider = AirdressIdentityProvider::new();
        assert!(
            !provider
                .valid_successor(
                    &leaf_for(&v1, &v1_pub),
                    &leaf_for(&v2, &v2_pub),
                    &mls_rs::ExtensionList::default()
                )
                .unwrap()
        );
    }

    // -- FR-18: expiry --

    #[test]
    fn spec_061_an_expired_delegation_is_rejected_with_and_without_a_timestamp() {
        let root = SigningKey::from_bytes(&[11u8; 32]);
        let root_pub = root.verifying_key().to_bytes();
        let (expired, session_pub) = v2_identity(
            &root,
            "alice.humans.airdress.co",
            22,
            "device-phone",
            "2026-09-05T11:00:00Z", // one hour before NOW
        );

        let provider = AirdressIdentityProvider::new();
        provider.set_root_key_lookup(std::sync::Arc::new(move |_: &str| Some(root_pub)));
        provider.set_clock(std::sync::Arc::new(FixedClock(NOW)));
        let leaf = leaf_for(&expired, &session_pub);

        // With a timestamp from mls-rs.
        assert_eq!(
            provider.validate_external_sender(&leaf, Some(mls_rs::time::MlsTime::from(NOW)), None),
            Err(CredentialVerifyError::DelegationExpired)
        );
        // And with none — the path mls-rs actually takes most of the
        // time. Skipping here would make expiry attacker-selectable.
        assert_eq!(
            provider.validate_external_sender(&leaf, None, None),
            Err(CredentialVerifyError::DelegationExpired)
        );
    }

    #[test]
    fn spec_061_a_delegation_expiring_in_an_hour_is_accepted() {
        let root = SigningKey::from_bytes(&[11u8; 32]);
        let root_pub = root.verifying_key().to_bytes();
        let (fresh, session_pub) = v2_identity(
            &root,
            "alice.humans.airdress.co",
            22,
            "device-phone",
            "2026-09-05T13:00:00Z", // one hour after NOW
        );

        let provider = AirdressIdentityProvider::new();
        provider.set_root_key_lookup(std::sync::Arc::new(move |_: &str| Some(root_pub)));
        provider.set_clock(std::sync::Arc::new(FixedClock(NOW)));
        let leaf = leaf_for(&fresh, &session_pub);
        provider
            .validate_external_sender(&leaf, None, None)
            .expect("not yet expired");
        provider
            .validate_member(
                &leaf,
                Some(mls_rs::time::MlsTime::from(NOW)),
                mls_rs_core::identity::MemberValidationContext::None,
            )
            .expect("not yet expired");
    }

    #[test]
    fn spec_061_a_v1_delegation_carrying_an_expiry_is_still_held_to_it() {
        // Labelling a delegation v1 must not be a way to keep an
        // expiry field and escape the check.
        let root = SigningKey::from_bytes(&[11u8; 32]);
        let root_pub = root.verifying_key().to_bytes();
        let session = SigningKey::from_bytes(&[22u8; 32]);
        let session_pub = session.verifying_key().to_bytes();
        let json = signed_delegation_json_v2(
            &root,
            "alice.humans.airdress.co",
            &session_pub,
            "device-phone",
            "2026-09-05T11:00:00Z",
        );
        let delegation: Value = serde_json::from_str(&json).unwrap();
        let mislabelled = AirdressIdentity {
            version: IdentityVersion::V1,
            airdress: "alice.humans.airdress.co".to_owned(),
            root_public_key: root_pub,
            delegation: delegation.as_object().unwrap().clone(),
        };

        assert_eq!(
            verify_identity_at(
                &mislabelled,
                &session_pub,
                &move |_: &str| Some(root_pub),
                None,
                NOW,
            ),
            Err(CredentialVerifyError::DelegationExpired)
        );
    }

    // -- FR-19: revocation --

    #[test]
    fn spec_061_a_revoked_device_is_rejected_and_an_unavailable_answer_is_too() {
        let root = SigningKey::from_bytes(&[11u8; 32]);
        let root_pub = root.verifying_key().to_bytes();
        let (identity, session_pub) = v2_identity(
            &root,
            "alice.humans.airdress.co",
            22,
            "device-phone",
            FAR_FUTURE,
        );
        let lookup = move |_: &str| Some(root_pub);

        let fresh = |_: &str| Some(DeviceStatus::Active);
        verify_identity_at(&identity, &session_pub, &lookup, Some(&fresh), NOW)
            .expect("an active device passes");

        let revoked = |_: &str| Some(DeviceStatus::Revoked);
        assert_eq!(
            verify_identity_at(&identity, &session_pub, &lookup, Some(&revoked), NOW),
            Err(CredentialVerifyError::DeviceRevoked)
        );

        // Fail closed, exactly like RootKeyUnavailable: a revocation
        // check that warns is not a revocation check.
        let unavailable = |_: &str| None;
        assert_eq!(
            verify_identity_at(&identity, &session_pub, &lookup, Some(&unavailable), NOW),
            Err(CredentialVerifyError::RevocationUnavailable)
        );
    }

    #[test]
    fn spec_061_revocation_is_keyed_on_the_device_id() {
        let root = SigningKey::from_bytes(&[11u8; 32]);
        let root_pub = root.verifying_key().to_bytes();
        let (identity, session_pub) = v2_identity(
            &root,
            "alice.humans.airdress.co",
            22,
            "device-phone",
            FAR_FUTURE,
        );
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let recorder = {
            let seen = seen.clone();
            move |device_id: &str| {
                seen.lock().unwrap().push(device_id.to_owned());
                Some(DeviceStatus::Active)
            }
        };
        verify_identity_at(
            &identity,
            &session_pub,
            &move |_: &str| Some(root_pub),
            Some(&recorder),
            NOW,
        )
        .unwrap();
        assert_eq!(seen.lock().unwrap().as_slice(), ["device-phone"]);
    }

    #[test]
    fn spec_061_the_revocation_socket_is_inert_until_a_host_registers_one() {
        // Same posture as check 2: a host that has not wired the
        // socket is in the pre-cutover state, not in a state where
        // nothing validates.
        let root = SigningKey::from_bytes(&[11u8; 32]);
        let root_pub = root.verifying_key().to_bytes();
        let (identity, session_pub) = v2_identity(
            &root,
            "alice.humans.airdress.co",
            22,
            "device-phone",
            FAR_FUTURE,
        );
        verify_identity_at(
            &identity,
            &session_pub,
            &move |_: &str| Some(root_pub),
            None,
            NOW,
        )
        .expect("no lookup registered means check 5 does not run");
    }

    // -- FR-20: the cutover --

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
        let leaf = leaf_for(&identity, &session_pub);
        assert!(provider.validate_external_sender(&leaf, None, None).is_ok());

        // Pre-cutover the member identity is still the bare airdress.
        assert_eq!(
            provider
                .identity(&leaf, &mls_rs::ExtensionList::default())
                .unwrap(),
            b"alice.humans.airdress.co".to_vec()
        );
    }

    #[test]
    fn spec_061_the_cutover_is_one_way_and_retires_v1() {
        let root = SigningKey::from_bytes(&[11u8; 32]);
        let root_pub = root.verifying_key().to_bytes();
        let (v1, _, v1_pub) = chain_fixture();
        let (v2, v2_pub) = v2_identity(
            &root,
            "alice.humans.airdress.co",
            33,
            "device-phone",
            FAR_FUTURE,
        );

        let provider = AirdressIdentityProvider::new();
        provider.set_root_key_lookup(std::sync::Arc::new(move |_: &str| Some(root_pub)));
        provider.set_clock(std::sync::Arc::new(FixedClock(NOW)));
        let v1_leaf = leaf_for(&v1, &v1_pub);
        let v2_leaf = leaf_for(&v2, &v2_pub);

        // Before: v1 works, v2 works.
        assert!(!provider.is_v2_cutover());
        provider
            .validate_external_sender(&v1_leaf, None, None)
            .expect("v1 accepted pre-cutover");
        provider
            .validate_external_sender(&v2_leaf, None, None)
            .expect("v2 accepted pre-cutover");

        // After: v1 is refused, v2 is the only live form.
        provider.set_v2_cutover();
        assert!(provider.is_v2_cutover());
        assert_eq!(
            provider.validate_external_sender(&v1_leaf, None, None),
            Err(CredentialVerifyError::LegacyIdentityRejected)
        );
        assert_eq!(
            provider.identity(&v1_leaf, &mls_rs::ExtensionList::default()),
            Err(CredentialVerifyError::LegacyIdentityRejected)
        );
        provider
            .validate_external_sender(&v2_leaf, None, None)
            .expect("v2 is the live form after the cutover");
    }
}
