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
//! - **`v: 3`** — the `v: 2` delegation plus `person_id`: a device of
//!   one *person* of an airdress who is not its owner (a household
//!   member). Such a person holds a root of their own, the **person
//!   root**, and it is that root which signs the delegation and sits in
//!   `root_public_key`. The member identity becomes
//!   `airdress ‖ 0x1F ‖ person_id ‖ 0x1F ‖ device_id`, and check 2
//!   looks the root up under the **pin subject**
//!   `airdress ‖ 0x1F ‖ person_id` instead of the bare airdress
//!   ([`AirdressIdentity::pin_subject`]). The owner keeps `v: 2` and
//!   the bare airdress, unchanged.
//!
//! Each added field is inside the object the root signs, so adding it
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

/// Separator between the airdress, the `person_id` and the `device_id`
/// in the member identity bytes and the pin subject (FR-16, design D-4).
///
/// ASCII unit separator: not legal in an airdress FQDN and not legal
/// in a UUID, so `airdress ‖ 0x1F ‖ device_id` and
/// `airdress ‖ 0x1F ‖ person_id ‖ 0x1F ‖ device_id` are unambiguous,
/// and never equal to each other. Every component is rejected if it
/// contains it, because "cannot occur" is only true of well-formed
/// inputs and none of the components is ours.
pub const IDENTITY_SEPARATOR: u8 = 0x1F;

/// The delegation field that names the person a `v: 3` delegation is
/// for. Inside the signed object, like every field a check reads.
pub const PERSON_ID_FIELD: &str = "person_id";

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
    /// The owner of an airdress, whose root is the airdress root.
    V2,
    /// A person of an airdress other than its owner: `v: 2` plus
    /// `person_id`, signed by that person's own root and pinned under
    /// `airdress ‖ 0x1F ‖ person_id` (SPEC-144).
    V3,
}

impl IdentityVersion {
    const fn wire_value(self) -> i64 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
            Self::V3 => 3,
        }
    }

    const fn from_wire(v: i64) -> Option<Self> {
        match v {
            1 => Some(Self::V1),
            2 => Some(Self::V2),
            3 => Some(Self::V3),
            _ => None,
        }
    }
}

/// The structured identity carried in the credential's identity bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AirdressIdentity {
    /// Which delegation form this is. Serialized as `v`.
    pub version: IdentityVersion,
    /// The airdress the delegation names.
    pub airdress: String,
    /// The Ed25519 public key that signed the delegation: the airdress
    /// root for `v: 1` and `v: 2`, the person root for `v: 3`.
    pub root_public_key: [u8; 32],
    /// The full delegation object, `signature` field included.
    pub delegation: Map<String, Value>,
}

impl AirdressIdentity {
    /// Build an identity around a delegation this device just minted,
    /// choosing the version from the delegation's own fields: a
    /// delegation carrying `person_id` is `v: 3`; otherwise one carrying
    /// both `device_id` and `expires_at` is `v: 2`; anything else is
    /// `v: 1`.
    ///
    /// `person_id` decides on its own, without the other two: a
    /// delegation naming a person that lacks a `device_id` or an expiry
    /// is a malformed `v: 3` that fails verification loudly, never a
    /// `v: 1` that would look its root up under the bare airdress.
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
        let version = if delegation.contains_key(PERSON_ID_FIELD) {
            IdentityVersion::V3
        } else if delegation.contains_key("device_id") && delegation.contains_key("expires_at") {
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

    /// The person a `v: 3` delegation is for, or `None` when the
    /// delegation does not name one (every `v: 1` and `v: 2` one).
    #[must_use]
    pub fn person_id(&self) -> Option<&str> {
        self.delegation.get(PERSON_ID_FIELD).and_then(Value::as_str)
    }

    /// The `person_id` of a `v: 3` identity, checked: present,
    /// non-empty, and free of the separator byte.
    fn checked_person_id(&self) -> Result<&str, CredentialVerifyError> {
        let person_id = self.person_id().filter(|p| !p.is_empty()).ok_or_else(|| {
            CredentialVerifyError::Malformed("v3 delegation missing person_id".into())
        })?;
        if person_id.as_bytes().contains(&IDENTITY_SEPARATOR) {
            return Err(CredentialVerifyError::Malformed(
                "person_id contains the identity separator".into(),
            ));
        }
        Ok(person_id)
    }

    /// What a peer pins this identity's root under, and so what check 2
    /// asks the host's [`RootKeyLookup`] for.
    ///
    /// - `v: 1` and `v: 2`: the bare airdress. Its root is the airdress
    ///   root, and every pin a peer already holds is under this string.
    /// - `v: 3`: `airdress ‖ 0x1F ‖ person_id`. A person's root is not
    ///   the airdress root, so it is pinned apart from it; and a host
    ///   that has never heard of persons receives a string it cannot
    ///   resolve and answers `None`, which rejects the leaf. That is the
    ///   safe failure for an old client meeting a new member.
    ///
    /// The airdress is the identity's own field; `person_id` is read
    /// from inside the signed delegation.
    ///
    /// # Errors
    ///
    /// [`CredentialVerifyError::Malformed`] when the airdress contains
    /// the separator byte, or a `v: 3` delegation carries no usable
    /// `person_id`.
    pub fn pin_subject(&self) -> Result<String, CredentialVerifyError> {
        if self.airdress.as_bytes().contains(&IDENTITY_SEPARATOR) {
            return Err(CredentialVerifyError::Malformed(
                "airdress contains the identity separator".into(),
            ));
        }
        match self.version {
            IdentityVersion::V1 | IdentityVersion::V2 => Ok(self.airdress.clone()),
            IdentityVersion::V3 => Ok(pin_subject_for_person(
                &self.airdress,
                self.checked_person_id()?,
            )),
        }
    }

    /// The member identity `mls-rs` uses to detect duplicate members
    /// (FR-16): `airdress ‖ 0x1F ‖ device_id` for `v: 2`,
    /// `airdress ‖ 0x1F ‖ person_id ‖ 0x1F ‖ device_id` for `v: 3`, the
    /// bare airdress for `v: 1`.
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
    /// [`CredentialVerifyError::MissingDeviceId`] when a `v: 2` or
    /// `v: 3` delegation carries no `device_id`;
    /// [`CredentialVerifyError::Malformed`] when any component contains
    /// the separator byte, or a `v: 3` delegation carries no
    /// `person_id`.
    pub fn member_identity(&self) -> Result<Vec<u8>, CredentialVerifyError> {
        if self.airdress.as_bytes().contains(&IDENTITY_SEPARATOR) {
            return Err(CredentialVerifyError::Malformed(
                "airdress contains the identity separator".into(),
            ));
        }
        match self.version {
            IdentityVersion::V1 => Ok(self.airdress.clone().into_bytes()),
            IdentityVersion::V2 => {
                let device_id = self.checked_device_id()?;
                let mut out = Vec::with_capacity(self.airdress.len() + 1 + device_id.len());
                out.extend_from_slice(self.airdress.as_bytes());
                out.push(IDENTITY_SEPARATOR);
                out.extend_from_slice(device_id.as_bytes());
                Ok(out)
            }
            IdentityVersion::V3 => {
                let subject = self.pin_subject()?;
                let device_id = self.checked_device_id()?;
                let mut out = Vec::with_capacity(subject.len() + 1 + device_id.len());
                out.extend_from_slice(subject.as_bytes());
                out.push(IDENTITY_SEPARATOR);
                out.extend_from_slice(device_id.as_bytes());
                Ok(out)
            }
        }
    }

    /// The `device_id` of a `v: 2` or `v: 3` identity, checked: present,
    /// non-empty, and free of the separator byte.
    fn checked_device_id(&self) -> Result<&str, CredentialVerifyError> {
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
        Ok(device_id)
    }
}

/// The pin subject of a person of `airdress` other than its owner:
/// `airdress ‖ 0x1F ‖ person_id`. What a host keys a person's pinned
/// root under, and what its [`RootKeyLookup`] receives for a `v: 3`
/// leaf. The owner's subject is the bare airdress.
#[must_use]
pub fn pin_subject_for_person(airdress: &str, person_id: &str) -> String {
    format!("{airdress}{}{person_id}", char::from(IDENTITY_SEPARATOR))
}

/// Split a pin subject into the airdress and, for a person other than
/// the owner, the `person_id`.
///
/// What a host's [`RootKeyLookup`] does first: the bare airdress
/// (`(airdress, None)`) is the owner's root, fetched as before;
/// `(airdress, Some(person_id))` is a person root, which a host that
/// does not know persons answers with `None`. Returns `None` for a
/// subject with more than one separator or an empty component, which
/// no identity produces.
#[must_use]
pub fn split_pin_subject(subject: &str) -> Option<(&str, Option<&str>)> {
    let sep = char::from(IDENTITY_SEPARATOR);
    let mut parts = subject.split(sep);
    let airdress = parts.next().filter(|a| !a.is_empty())?;
    match (parts.next(), parts.next()) {
        (None, _) => Some((airdress, None)),
        (Some(person), None) if !person.is_empty() => Some((airdress, Some(person))),
        _ => None,
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
/// Rules: bytes that parse as a JSON object with a known `"v"` (1, 2
/// or 3) are the structured form and must then be fully well-formed (an
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
#[expect(
    clippy::map_err_ignore,
    reason = "the discarded errors are a Vec handed back by try_into or a base64/UTF-8 position; the closed error kinds returned say all a caller can act on"
)]
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
    /// Check 4 could not run: the clock reads before 1970, so "now"
    /// is unknown. A reject — reading it as 0 would make every expiry
    /// lie in the future, which is a wound-back clock accepting expired
    /// delegations.
    ClockUnavailable,
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
            Self::ClockUnavailable => write!(f, "system clock unavailable"),
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
///
/// The argument is a **pin subject** ([`AirdressIdentity::pin_subject`]):
/// the bare airdress for an owner's leaf (`v: 1`, `v: 2`), and
/// `airdress ‖ 0x1F ‖ person_id` for another person's (`v: 3`).
/// [`split_pin_subject`] tells the two apart. A host that does not
/// resolve person roots answers `None` for the second form, which
/// rejects the leaf.
pub trait RootKeyLookup: Send + Sync {
    /// The root public key cached for the pin subject `airdress`, or
    /// `None`, which rejects.
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
    /// Whether `device_id` is active or revoked, or `None` when the
    /// answer is unknown, which rejects.
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

    /// Seconds since the Unix epoch, or `None` when the clock cannot
    /// say — what verification reads, so that an unknown "now" refuses
    /// a delegation with an expiry instead of passing it. The default
    /// trusts [`Self::now_unix_seconds`].
    fn now_unix_seconds_checked(&self) -> Option<u64> {
        Some(self.now_unix_seconds())
    }
}

/// Production [`Clock`]: the host's wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    /// 0 for a clock before 1970. Verification never reads this form:
    /// it reads [`Clock::now_unix_seconds_checked`], which refuses.
    fn now_unix_seconds(&self) -> u64 {
        self.now_unix_seconds_checked().unwrap_or(0)
    }

    /// `None` for a clock before 1970.
    fn now_unix_seconds_checked(&self) -> Option<u64> {
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs())
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

/// The airdress a leaf belongs to, read out of its credential.
///
/// Both identity forms carry it: the structured form in its
/// `airdress` field, the legacy bare-string form as the whole string.
/// This is deliberately *not* [`AirdressIdentity::member_identity`] —
/// that value is per-device, and the question this answers is "whose
/// device is this?", which is what SPEC-061 FR-25 turns on.
///
/// Verification is a separate concern and is not performed here. A
/// caller using this to make an authorization decision is reading an
/// identity `mls-rs` has already validated through the identity
/// provider.
///
/// # Errors
///
/// [`CredentialVerifyError::Malformed`] when the credential is not a
/// basic credential or its identity bytes do not parse.
pub fn airdress_of(
    signing_identity: &mls_rs::identity::SigningIdentity,
) -> Result<String, CredentialVerifyError> {
    let basic = signing_identity.credential.as_basic().ok_or_else(|| {
        CredentialVerifyError::Malformed("credential is not a basic credential".into())
    })?;
    match parse_identity(&basic.identifier).map_err(CredentialVerifyError::Malformed)? {
        ParsedIdentity::Structured(identity) => Ok(identity.airdress),
        ParsedIdentity::Legacy(airdress) => Ok(airdress),
    }
}

/// Run the chain verification on a parsed identity with the system
/// clock and **no revocation check** (check 5 is skipped).
///
/// The name says what it leaves out (it was `verify_identity`, which
/// read as the whole check): a revoked device's identity passes here.
/// Use [`verify_identity_at`] with a revocation lookup, or a
/// cutover [`AirdressIdentityProvider`] with one registered, for a
/// leaf that is going into a group. Check 4 runs whenever the
/// delegation carries an expiry, and a clock before 1970 refuses it.
///
/// # Errors
///
/// Any [`CredentialVerifyError`].
pub fn verify_identity_without_revocation(
    identity: &AirdressIdentity,
    leaf_signing_key: &[u8],
    lookup: &dyn RootKeyLookup,
) -> Result<(), CredentialVerifyError> {
    verify_chain(
        identity,
        leaf_signing_key,
        Some(lookup),
        None,
        SystemClock.now_unix_seconds_checked(),
    )
}

/// [`verify_identity_without_revocation`] with the SPEC-061 sockets supplied explicitly:
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
        Some(now_unix_seconds),
    )
}

/// Checks 1, 3, 4 and 5 always; check 2 when a root lookup is
/// present. The lookup-less form exists ONLY for the pre-cutover
/// compat mode of [`AirdressIdentityProvider`] — strict verification
/// always supplies a lookup, and check 2 is then a hard reject in
/// every outcome.
#[expect(
    clippy::map_err_ignore,
    reason = "the discarded errors are a Vec handed back by try_into, a base64 position or an opaque ed25519 error; the closed error kinds returned say all a caller can act on"
)]
fn verify_chain(
    identity: &AirdressIdentity,
    leaf_signing_key: &[u8],
    lookup: Option<&dyn RootKeyLookup>,
    revocation: Option<&dyn RevocationLookup>,
    now_unix_seconds: Option<u64>,
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
    // or a mismatch is a hard reject, never a warning. Asked under the
    // pin subject: the bare airdress for the owner, the airdress and
    // the signed `person_id` for another person, whose root is their
    // own and never the airdress root.
    if let Some(lookup) = lookup {
        let published = lookup
            .root_public_key(&identity.pin_subject()?)
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

    // Check 4 (FR-18) — expiry. A `v: 2` or `v: 3` delegation MUST carry
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
            let now = now_unix_seconds.ok_or(CredentialVerifyError::ClockUnavailable)?;
            if expiry <= now {
                return Err(CredentialVerifyError::DelegationExpired);
            }
        }
        (IdentityVersion::V2, None) => {
            return Err(CredentialVerifyError::Malformed(
                "v2 delegation missing expires_at".into(),
            ));
        }
        (IdentityVersion::V3, None) => {
            return Err(CredentialVerifyError::Malformed(
                "v3 delegation missing expires_at".into(),
            ));
        }
        (IdentityVersion::V1, None) => {}
    }

    // Check 5 (FR-19) — revocation, keyed on the stable `device_id`,
    // for every version: a person's device is revoked like any other.
    // A `v: 2` or `v: 3` delegation must carry one; a `v: 1` delegation that
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
        (IdentityVersion::V2 | IdentityVersion::V3, _) => {
            return Err(CredentialVerifyError::MissingDeviceId);
        }
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
pub(crate) fn parse_rfc3339_seconds(s: &str) -> Option<u64> {
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

/// Format seconds since the Unix epoch as `YYYY-MM-DDThh:mm:ssZ`, the
/// form [`parse_rfc3339_seconds`] reads back exactly. `None` past year
/// 9999, which a four-digit year cannot carry.
pub(crate) fn format_rfc3339_seconds(unix: u64) -> Option<String> {
    let secs = i64::try_from(unix).ok()?;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (year, month, day) = civil_from_days(days);
    if year > 9999 {
        return None;
    }
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    ))
}

/// The inverse of [`days_from_civil`] (Howard Hinnant's `civil_from_days`).
const fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
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
    /// A provider in compatibility mode, before any lookup is set.
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

    /// Whether the v2 credential cutover has been entered.
    #[must_use]
    pub fn is_v2_cutover(&self) -> bool {
        self.v2_cutover.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// # Panics
    ///
    /// If the clock lock is poisoned — unrecoverable.
    fn now(&self, timestamp: Option<mls_rs::time::MlsTime>) -> Option<u64> {
        timestamp.map_or_else(
            || {
                self.clock
                    .read()
                    .expect("clock lock poisoned")
                    .now_unix_seconds_checked()
            },
            |t| Some(t.seconds_since_epoch()),
        )
    }

    /// The registered revocation lookup, if any, with no cutover
    /// refusal. What the MLS rules read when a `Remove` of another
    /// person's leaf needs the revocation witness: there, "no lookup"
    /// is simply "no witness", which refuses the removal.
    ///
    /// # Panics
    ///
    /// If the revocation lock is poisoned — unrecoverable.
    pub(crate) fn registered_revocation_lookup(
        &self,
    ) -> Option<std::sync::Arc<dyn RevocationLookup>> {
        self.revocation
            .read()
            .expect("revocation lock poisoned")
            .clone()
    }

    /// The registered revocation lookup, or a refusal when the v2
    /// cutover is on and none is registered.
    ///
    /// Past the cutover every leaf carries a `device_id` and check 5 is
    /// what makes removing a device mean anything. Before this, a host
    /// that entered the cutover and never registered a lookup skipped
    /// check 5 for every leaf, silently: a revoked device kept its seat.
    /// Now that host refuses every leaf until it registers one, which
    /// is loud (owner decision: fail closed).
    ///
    /// # Panics
    ///
    /// If the revocation lock is poisoned — unrecoverable.
    fn revocation_for_check(
        &self,
    ) -> Result<Option<std::sync::Arc<dyn RevocationLookup>>, CredentialVerifyError> {
        let revocation = self
            .revocation
            .read()
            .expect("revocation lock poisoned")
            .clone();
        if revocation.is_none() && self.is_v2_cutover() {
            return Err(CredentialVerifyError::RevocationUnavailable);
        }
        Ok(revocation)
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
        let revocation = self.revocation_for_check()?;
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
            ParsedIdentity::Structured(identity) => {
                let revocation = self.revocation_for_check()?;
                verify_chain(
                    &identity,
                    signing_identity.signature_key.as_bytes(),
                    lookup.as_deref(),
                    revocation.as_deref(),
                    self.now(timestamp),
                )
            }
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

/// Shared helpers for tests, in this crate and (behind the
/// `test-support` feature) in its consumers: a valid root-signed
/// delegation for a given session key.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
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

    /// The `v: 3` form: the `v: 2` object plus `person_id`, signed by
    /// `person_root` — that person's own root, not the airdress root.
    pub fn signed_delegation_json_v3(
        person_root: &SigningKey,
        airdress: &str,
        person_id: &str,
        session_public_key: &[u8; 32],
        device_id: &str,
        expires_at: &str,
    ) -> String {
        let mut obj = base(airdress, session_public_key);
        obj.insert("person_id".to_owned(), Value::from(person_id));
        obj.insert("device_id".to_owned(), Value::from(device_id));
        obj.insert("expires_at".to_owned(), Value::from(expires_at));
        sign(person_root, obj)
    }
}

#[cfg(test)]
mod tests {
    use mls_rs::identity::basic::BasicCredential;
    use serde_json::{Value, json};

    use super::{AirdressIdentity, IdentityVersion, ParsedIdentity, parse_identity};

    fn fixture_identity() -> AirdressIdentity {
        // Vector "minimal-realistic" from the shared fixture.
        let parsed: Value = serde_json::from_str(crate::vectors::DELEGATION).unwrap();
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
        let parsed: Value = serde_json::from_str(crate::vectors::DELEGATION).unwrap();
        let vector = parsed["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == json!("v2-delegation"))
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

    /// The `v: 3` vector in the shared fixture: a household member's
    /// delegation, signed by that person's own root. Also returns the
    /// vector's `identity` block, which carries the expected pin
    /// subject and member identity for every implementation to match.
    fn fixture_identity_v3() -> (AirdressIdentity, Value) {
        let parsed: Value = serde_json::from_str(crate::vectors::DELEGATION).unwrap();
        let vector = parsed["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == json!("person-v3-delegation"))
            .expect("fixture carries the person vector")
            .clone();
        let identity = AirdressIdentity {
            version: IdentityVersion::V3,
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
        };
        (identity, vector["identity"].clone())
    }

    #[test]
    fn v3_identity_bytes_round_trip() {
        let (identity, _) = fixture_identity_v3();
        let bytes = identity.to_identity_bytes().unwrap();
        let as_value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(as_value["v"], json!(3));

        match parse_identity(&bytes).unwrap() {
            ParsedIdentity::Structured(back) => {
                assert_eq!(back, identity);
                assert_eq!(back.version, IdentityVersion::V3);
                assert_eq!(
                    back.person_id(),
                    Some("019f3c2a-5e71-7b04-a8d3-4e1f9c6b2a85")
                );
            }
            ParsedIdentity::Legacy(_) => panic!("v3 identity parsed as legacy"),
        }
    }

    #[test]
    fn the_person_vector_names_its_pin_subject_and_member_identity() {
        // The vector carries both strings so the phone (over FFI) and
        // the operator check the same bytes this crate produces.
        let (identity, expected) = fixture_identity_v3();
        assert_eq!(expected["v"], json!(3));
        assert_eq!(
            identity.pin_subject().unwrap(),
            expected["pin_subject"].as_str().unwrap()
        );
        assert_eq!(
            identity.member_identity().unwrap(),
            expected["member_identity"].as_str().unwrap().as_bytes()
        );
        assert_eq!(
            super::split_pin_subject(&identity.pin_subject().unwrap()),
            Some((
                "alice.humans.airdress.co",
                Some("019f3c2a-5e71-7b04-a8d3-4e1f9c6b2a85")
            ))
        );
    }

    #[test]
    fn owner_forms_keep_the_bare_airdress_as_their_pin_subject() {
        let v1 = fixture_identity();
        let v2 = fixture_identity_v2();
        assert_eq!(v1.pin_subject().unwrap(), "alice.humans.airdress.co");
        assert_eq!(v2.pin_subject().unwrap(), v2.airdress);
        assert_eq!(
            super::split_pin_subject("alice.humans.airdress.co"),
            Some(("alice.humans.airdress.co", None))
        );
    }

    #[test]
    fn a_pin_subject_no_identity_produces_does_not_split() {
        for bad in ["", "\u{1f}p", "a\u{1f}", "a\u{1f}p\u{1f}d"] {
            assert_eq!(super::split_pin_subject(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn version_is_inferred_from_the_delegations_own_fields() {
        let v1 = fixture_identity();
        let inferred_v1 =
            AirdressIdentity::from_delegation(v1.airdress, v1.root_public_key, v1.delegation);
        assert_eq!(inferred_v1.version, IdentityVersion::V1);

        let v2 = fixture_identity_v2();
        let inferred_v2 =
            AirdressIdentity::from_delegation(v2.airdress, v2.root_public_key, v2.delegation);
        assert_eq!(inferred_v2.version, IdentityVersion::V2);

        let (v3, _) = fixture_identity_v3();
        let inferred_v3 = AirdressIdentity::from_delegation(
            v3.airdress.clone(),
            v3.root_public_key,
            v3.delegation.clone(),
        );
        assert_eq!(inferred_v3.version, IdentityVersion::V3);

        // `person_id` decides on its own: without an expiry the
        // delegation is a malformed v3, never a v1 pinned under the
        // bare airdress.
        let mut no_expiry = v3.delegation;
        no_expiry.remove("expires_at");
        let inferred =
            AirdressIdentity::from_delegation(v3.airdress, v3.root_public_key, no_expiry);
        assert_eq!(inferred.version, IdentityVersion::V3);
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
        // A future v:4 must fail loudly rather than be demoted to a
        // bare-string airdress, which would drop every check.
        let bytes = br#"{"v":4,"airdress":"alice.test","root_public_key":"","delegation":{}}"#;
        assert!(parse_identity(bytes).is_err());
    }

    #[test]
    fn a_malformed_v3_is_refused() {
        // `v: 3` is a known version now; known means held to its
        // fields, never demoted to legacy.
        let bytes = br#"{"v":3,"airdress":"alice.test","root_public_key":"","delegation":{}}"#;
        assert!(parse_identity(bytes).is_err());
        assert!(parse_identity(br#"{"v":3,"airdress":"alice.test"}"#).is_err());
    }

    #[test]
    fn versioned_object_with_bad_fields_is_an_error_not_legacy() {
        assert!(parse_identity(br#"{"v":1,"airdress":"alice.test"}"#).is_err());
        assert!(parse_identity(br#"{"v":2,"airdress":"alice.test"}"#).is_err());
        assert!(parse_identity(br#"{"v":3,"airdress":"alice.test"}"#).is_err());
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
    fn rfc3339_formatting_round_trips() {
        use super::format_rfc3339_seconds;
        for unix in [0, 951_782_400, 1_709_164_800, 1_791_201_600, 4_102_444_799] {
            let text = format_rfc3339_seconds(unix).unwrap();
            assert_eq!(parse_rfc3339_seconds(&text), Some(unix), "{text}");
        }
        assert_eq!(
            format_rfc3339_seconds(1_791_201_600).as_deref(),
            Some("2026-10-05T12:00:00Z")
        );
        assert_eq!(format_rfc3339_seconds(u64::MAX), None);
        assert_eq!(format_rfc3339_seconds(253_402_300_800), None);
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
        IDENTITY_SEPARATOR, verify_identity_at, verify_identity_without_revocation,
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
        verify_identity_without_revocation(&identity, &session_pub, &lookup).unwrap();
    }

    #[test]
    fn wrong_published_root_is_rejected() {
        let (identity, _, session_pub) = chain_fixture();
        let other_root = SigningKey::from_bytes(&[99u8; 32])
            .verifying_key()
            .to_bytes();
        let lookup = move |_: &str| Some(other_root);
        assert_eq!(
            verify_identity_without_revocation(&identity, &session_pub, &lookup),
            Err(CredentialVerifyError::RootKeyMismatch)
        );
    }

    #[test]
    fn unavailable_published_root_is_rejected() {
        let (identity, _, session_pub) = chain_fixture();
        let lookup = |_: &str| None;
        assert_eq!(
            verify_identity_without_revocation(&identity, &session_pub, &lookup),
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
            verify_identity_without_revocation(&identity, &other_session, &lookup),
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
            verify_identity_without_revocation(&identity, &session_pub, &lookup),
            Err(CredentialVerifyError::DelegationSignatureInvalid)
        );
    }

    // -- FR-16: the member identity is per-device --

    #[test]
    fn two_devices_of_one_airdress_get_different_identities() {
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
    fn v1_identity_is_still_the_bare_airdress() {
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
    fn a_separator_byte_in_either_component_is_refused() {
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
    fn v2_without_a_device_id_is_refused() {
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
    fn a_sibling_device_is_not_a_valid_successor() {
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
    fn a_re_delegated_device_keeps_its_leaf() {
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
    fn the_same_device_under_a_different_root_is_not_a_successor() {
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
    fn a_v1_leaf_cannot_be_succeeded_by_a_v2_leaf() {
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
    fn an_expired_delegation_is_rejected_with_and_without_a_timestamp() {
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
    fn a_delegation_expiring_in_an_hour_is_accepted() {
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
    fn a_v1_delegation_carrying_an_expiry_is_still_held_to_it() {
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
    fn a_revoked_device_is_rejected_and_an_unavailable_answer_is_too() {
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
    fn revocation_is_keyed_on_the_device_id() {
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
    fn the_revocation_socket_is_inert_until_a_host_registers_one() {
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
    fn the_cutover_is_one_way_and_retires_v1() {
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
        // Fail closed: past the cutover, no revocation lookup means no
        // leaf verifies — not every leaf skipping check 5.
        assert_eq!(
            provider.validate_external_sender(&v2_leaf, None, None),
            Err(CredentialVerifyError::RevocationUnavailable)
        );
        provider.set_revocation_lookup(std::sync::Arc::new(|_: &str| Some(DeviceStatus::Active)));
        provider
            .validate_external_sender(&v2_leaf, None, None)
            .expect("v2 is the live form after the cutover");

        // And a clock that cannot say what time it is refuses a v2 leaf
        // rather than reading "now" as 1970, before every expiry.
        provider.set_clock(std::sync::Arc::new(BeforeEpoch));
        assert_eq!(
            provider.validate_external_sender(&v2_leaf, None, None),
            Err(CredentialVerifyError::ClockUnavailable)
        );
    }

    /// A clock before 1970, as `SystemClock` reads one.
    struct BeforeEpoch;

    impl super::Clock for BeforeEpoch {
        fn now_unix_seconds(&self) -> u64 {
            0
        }

        fn now_unix_seconds_checked(&self) -> Option<u64> {
            None
        }
    }

    // -- v: 3, a person of the airdress other than its owner --

    const AIRDRESS: &str = "alice.humans.airdress.co";
    const SAM: &str = "019f3c2a-5e71-7b04-a8d3-4e1f9c6b2a85";
    const ROBIN: &str = "019f3c2a-6a10-7d55-9e02-b3c4d5e6f708";

    /// A `v: 3` identity for one device of `person_id`, signed by
    /// `person_root`: `(identity, session_pub)`.
    fn v3_identity(
        person_root: &SigningKey,
        person_id: &str,
        session_seed: u8,
        device_id: &str,
    ) -> (AirdressIdentity, [u8; 32]) {
        let session = SigningKey::from_bytes(&[session_seed; 32]);
        let session_pub = session.verifying_key().to_bytes();
        let json = super::test_support::signed_delegation_json_v3(
            person_root,
            AIRDRESS,
            person_id,
            &session_pub,
            device_id,
            FAR_FUTURE,
        );
        let delegation: Value = serde_json::from_str(&json).unwrap();
        (
            AirdressIdentity::from_delegation(
                AIRDRESS.to_owned(),
                person_root.verifying_key().to_bytes(),
                delegation.as_object().unwrap().clone(),
            ),
            session_pub,
        )
    }

    /// What a recording lookup was asked for.
    type Asked = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

    /// A root lookup that answers exactly one subject, and records
    /// every subject it was asked for.
    fn one_subject_lookup(
        subject: String,
        root: [u8; 32],
    ) -> (impl Fn(&str) -> Option<[u8; 32]> + Send + Sync, Asked) {
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = asked.clone();
        let lookup = move |s: &str| {
            seen.lock().unwrap().push(s.to_owned());
            (s == subject).then_some(root)
        };
        (lookup, asked)
    }

    #[test]
    fn a_v3_leaf_is_checked_against_its_person_root_under_the_person_subject() {
        let sam_root = SigningKey::from_bytes(&[0x51; 32]);
        let (identity, session_pub) = v3_identity(&sam_root, SAM, 0x61, "sam-phone");
        assert_eq!(identity.version, IdentityVersion::V3);
        let subject = super::pin_subject_for_person(AIRDRESS, SAM);
        let (lookup, asked) =
            one_subject_lookup(subject.clone(), sam_root.verifying_key().to_bytes());
        let active = |_: &str| Some(DeviceStatus::Active);
        verify_identity_at(&identity, &session_pub, &lookup, Some(&active), NOW)
            .expect("a member's device chains to the member's own root");
        assert_eq!(*asked.lock().unwrap(), vec![subject]);
    }

    #[test]
    fn a_v3_leaf_is_refused_by_a_host_that_only_answers_the_bare_airdress() {
        // The host of today: it pins roots by airdress and has never
        // heard of persons. It is asked a subject it cannot resolve
        // and answers None, which rejects the leaf, even if the key it
        // holds for the airdress happened to be this person's.
        let sam_root = SigningKey::from_bytes(&[0x51; 32]);
        let (identity, session_pub) = v3_identity(&sam_root, SAM, 0x61, "sam-phone");
        let (lookup, _) =
            one_subject_lookup(AIRDRESS.to_owned(), sam_root.verifying_key().to_bytes());
        let active = |_: &str| Some(DeviceStatus::Active);
        assert_eq!(
            verify_identity_at(&identity, &session_pub, &lookup, Some(&active), NOW),
            Err(CredentialVerifyError::RootKeyUnavailable)
        );
    }

    #[test]
    fn a_v3_leaf_is_refused_when_its_subject_holds_another_root() {
        // The airdress root (the owner's) answered under the person's
        // subject is a mismatch like any other.
        let owner_root = SigningKey::from_bytes(&[11u8; 32]);
        let sam_root = SigningKey::from_bytes(&[0x51; 32]);
        let (identity, session_pub) = v3_identity(&sam_root, SAM, 0x61, "sam-phone");
        let (lookup, _) = one_subject_lookup(
            super::pin_subject_for_person(AIRDRESS, SAM),
            owner_root.verifying_key().to_bytes(),
        );
        let active = |_: &str| Some(DeviceStatus::Active);
        assert_eq!(
            verify_identity_at(&identity, &session_pub, &lookup, Some(&active), NOW),
            Err(CredentialVerifyError::RootKeyMismatch)
        );
    }

    #[test]
    fn the_owner_v2_leaf_is_still_looked_up_under_the_bare_airdress() {
        let owner_root = SigningKey::from_bytes(&[11u8; 32]);
        let (identity, session_pub) =
            v2_identity(&owner_root, AIRDRESS, 22, "owner-phone", FAR_FUTURE);
        let (lookup, asked) =
            one_subject_lookup(AIRDRESS.to_owned(), owner_root.verifying_key().to_bytes());
        let active = |_: &str| Some(DeviceStatus::Active);
        verify_identity_at(&identity, &session_pub, &lookup, Some(&active), NOW)
            .expect("v2 verification is unchanged");
        assert_eq!(*asked.lock().unwrap(), vec![AIRDRESS.to_owned()]);
    }

    #[test]
    fn a_separator_byte_in_the_person_id_is_refused() {
        let sam_root = SigningKey::from_bytes(&[0x51; 32]);
        let (identity, session_pub) = v3_identity(&sam_root, "sam\u{1f}robin", 0x61, "sam-phone");
        assert!(matches!(
            identity.pin_subject(),
            Err(CredentialVerifyError::Malformed(_))
        ));
        assert!(matches!(
            identity.member_identity(),
            Err(CredentialVerifyError::Malformed(_))
        ));
        let lookup = |_: &str| Some(sam_root.verifying_key().to_bytes());
        let active = |_: &str| Some(DeviceStatus::Active);
        assert!(matches!(
            verify_identity_at(&identity, &session_pub, &lookup, Some(&active), NOW),
            Err(CredentialVerifyError::Malformed(_))
        ));
    }

    #[test]
    fn a_v3_without_its_fields_is_refused() {
        let sam_root = SigningKey::from_bytes(&[0x51; 32]);
        let lookup = |_: &str| Some(sam_root.verifying_key().to_bytes());
        let active = |_: &str| Some(DeviceStatus::Active);
        let (identity, session_pub) = v3_identity(&sam_root, SAM, 0x61, "sam-phone");

        // An empty person_id: no subject to pin under. (The field is
        // inside the signature, so this fails before check 1 would.)
        let mut empty = identity.clone();
        empty
            .delegation
            .insert("person_id".to_owned(), Value::from(""));
        assert!(matches!(
            empty.pin_subject(),
            Err(CredentialVerifyError::Malformed(_))
        ));

        // A v3 that names no device: no member identity, no revocation key.
        let mut no_device = identity.clone();
        no_device.delegation.remove("device_id");
        assert_eq!(
            no_device.member_identity(),
            Err(CredentialVerifyError::MissingDeviceId)
        );

        // A v3 with no expiry, re-signed so check 1 passes and the
        // expiry rule is what refuses it.
        let mut obj = identity.delegation;
        obj.remove("signature");
        obj.remove("expires_at");
        let canonical = crate::canonical::canonical_delegation_bytes(&obj).unwrap();
        let sig = ed25519_dalek::Signer::sign(&sam_root, &canonical);
        obj.insert(
            "signature".to_owned(),
            Value::from({
                use base64::Engine as _;
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes())
            }),
        );
        let no_expiry = AirdressIdentity::from_delegation(
            AIRDRESS.to_owned(),
            sam_root.verifying_key().to_bytes(),
            obj,
        );
        assert_eq!(no_expiry.version, IdentityVersion::V3);
        assert_eq!(
            verify_identity_at(&no_expiry, &session_pub, &lookup, Some(&active), NOW),
            Err(CredentialVerifyError::Malformed(
                "v3 delegation missing expires_at".into()
            ))
        );
    }

    #[test]
    fn a_revoked_member_device_is_refused_by_device_id() {
        let sam_root = SigningKey::from_bytes(&[0x51; 32]);
        let (identity, session_pub) = v3_identity(&sam_root, SAM, 0x61, "sam-phone");
        let lookup = |_: &str| Some(sam_root.verifying_key().to_bytes());
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seen = asked.clone();
        let revoked = move |d: &str| {
            seen.lock().unwrap().push(d.to_owned());
            Some(DeviceStatus::Revoked)
        };
        assert_eq!(
            verify_identity_at(&identity, &session_pub, &lookup, Some(&revoked), NOW),
            Err(CredentialVerifyError::DeviceRevoked)
        );
        assert_eq!(*asked.lock().unwrap(), vec!["sam-phone".to_owned()]);
    }

    #[test]
    fn member_identities_of_owner_and_persons_never_collide() {
        let owner_root = SigningKey::from_bytes(&[11u8; 32]);
        let sam_root = SigningKey::from_bytes(&[0x51; 32]);
        let robin_root = SigningKey::from_bytes(&[0x52; 32]);
        // The same device id under three people.
        let (owner, owner_pub) = v2_identity(&owner_root, AIRDRESS, 22, "phone-1", FAR_FUTURE);
        let (sam, sam_pub) = v3_identity(&sam_root, SAM, 0x61, "phone-1");
        let (robin, robin_pub) = v3_identity(&robin_root, ROBIN, 0x62, "phone-1");

        let provider = AirdressIdentityProvider::new();
        let ext = mls_rs::ExtensionList::default();
        let ids = [
            provider
                .identity(&leaf_for(&owner, &owner_pub), &ext)
                .unwrap(),
            provider.identity(&leaf_for(&sam, &sam_pub), &ext).unwrap(),
            provider
                .identity(&leaf_for(&robin, &robin_pub), &ext)
                .unwrap(),
        ];
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[0], ids[2]);
        assert_ne!(ids[1], ids[2]);
        assert_eq!(
            ids[1],
            [
                AIRDRESS.as_bytes(),
                &[IDENTITY_SEPARATOR],
                SAM.as_bytes(),
                &[IDENTITY_SEPARATOR],
                b"phone-1"
            ]
            .concat()
        );
    }

    #[test]
    fn valid_successor_refuses_across_versions_and_across_persons() {
        let sam_root = SigningKey::from_bytes(&[0x51; 32]);
        let provider = AirdressIdentityProvider::new();
        let ext = mls_rs::ExtensionList::default();
        let (sam, sam_pub) = v3_identity(&sam_root, SAM, 0x61, "phone-1");

        // The same device re-delegated by the same person: still the member.
        let (sam_again, sam_again_pub) = v3_identity(&sam_root, SAM, 0x63, "phone-1");
        assert!(
            provider
                .valid_successor(
                    &leaf_for(&sam, &sam_pub),
                    &leaf_for(&sam_again, &sam_again_pub),
                    &ext
                )
                .unwrap()
        );

        // Same device id, same root, another person: a different member.
        let (other, other_pub) = v3_identity(&sam_root, ROBIN, 0x61, "phone-1");
        assert!(
            !provider
                .valid_successor(
                    &leaf_for(&sam, &sam_pub),
                    &leaf_for(&other, &other_pub),
                    &ext
                )
                .unwrap()
        );

        // Same device id, same root, as v2: a different form, never a successor,
        // in either direction.
        let (as_v2, as_v2_pub) = v2_identity(&sam_root, AIRDRESS, 0x61, "phone-1", FAR_FUTURE);
        assert!(
            !provider
                .valid_successor(
                    &leaf_for(&as_v2, &as_v2_pub),
                    &leaf_for(&sam, &sam_pub),
                    &ext
                )
                .unwrap()
        );
        assert!(
            !provider
                .valid_successor(
                    &leaf_for(&sam, &sam_pub),
                    &leaf_for(&as_v2, &as_v2_pub),
                    &ext
                )
                .unwrap()
        );
    }

    #[test]
    fn v3_is_a_live_form_past_the_cutover() {
        let sam_root = SigningKey::from_bytes(&[0x51; 32]);
        let (sam, sam_pub) = v3_identity(&sam_root, SAM, 0x61, "sam-phone");
        let sam_root_pub = sam_root.verifying_key().to_bytes();
        let subject = super::pin_subject_for_person(AIRDRESS, SAM);
        let provider = AirdressIdentityProvider::new();
        provider.set_root_key_lookup(std::sync::Arc::new(move |s: &str| {
            (s == subject).then_some(sam_root_pub)
        }));
        provider.set_clock(std::sync::Arc::new(FixedClock(NOW)));
        provider.set_revocation_lookup(std::sync::Arc::new(|_: &str| Some(DeviceStatus::Active)));
        provider.set_v2_cutover();
        provider
            .validate_external_sender(&leaf_for(&sam, &sam_pub), None, None)
            .expect("a member's leaf validates past the cutover");
    }
}
