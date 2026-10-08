//! Airdress MLS rules: who may remove whom.
//!
//! ## The rule
//!
//! Two layers, the second inside the first.
//!
//! 1. **Per airdress (SPEC-061 FR-25).** A member may propose `Remove`
//!    only for leaves under its **own** airdress. Bob cannot evict one
//!    of Alice's devices. Unchanged, and still checked first.
//! 2. **Per person, once a `v: 3` leaf is involved (SPEC-144 F-7,
//!    owner ruling 2026-10-07).** Inside one airdress, a member may
//!    propose `Remove` only for leaves with its **own** pin subject
//!    ([`AirdressIdentity::pin_subject`]): the owner's devices remove
//!    the owner's devices, and each household member's devices remove
//!    that member's devices. A member never removes the owner's
//!    devices, and the owner never removes a member's live devices.
//!
//! When neither the proposer nor the target is a `v: 3` leaf, layer 2
//! never runs, so `v: 1`, `v: 2` and legacy groups behave exactly as
//! before.
//!
//! ## The one exception: a revoked person's devices (SPEC-144 FR-53)
//!
//! When a household member is revoked or retired, the peers that hold
//! a group with them commit the Remove of their leaves (design §8.3);
//! the owner's devices do it as peers, not as the owner. So a `Remove`
//! of **another person's `v: 3` leaf** is admitted when, and only when,
//! the **revocation witness** holds:
//!
//! > the host's check-5 [`RevocationLookup`], asked for the target
//! > leaf's `device_id`, answers [`DeviceStatus::Revoked`].
//!
//! The witness is evaluated by **each device against its own lookup**,
//! on both directions: the committer when it builds the commit, every
//! receiver when it processes it. Nothing the proposer writes is
//! trusted — there is no proof in the commit, and the proposer cannot
//! name a device revoked; it can only be right about it. Consequences,
//! all deliberate:
//!
//! - **The exception cannot be turned against a live person.** A
//!   receiver whose lookup says `Active` refuses the commit, and so does
//!   one with no answer (`None`) or no lookup registered at all: no
//!   witness is a refusal, the same fail-closed direction check 5 takes.
//! - **It never reaches the owner's devices.** The exception is for
//!   `v: 3` targets only. A revoked owner device is removed by the
//!   owner's other devices, under the per-person rule itself.
//! - **It never crosses airdresses.** Layer 1 is checked first, and a
//!   correspondent's remedy is still to leave the conversation.
//! - **A receiver whose view is stale refuses, and can retry.** The
//!   operator records the revocation before it announces
//!   `sibling_revoked`, and every device of the airdress reads its
//!   revocation state from that same operator. A device that refuses a
//!   commit with [`MlsRulesError::CrossPersonRemoval`] refreshes its
//!   revocation state and processes the same commit again: a refused
//!   commit persists nothing, so the retry starts from the same epoch.
//!   A device that still answers `Active` after a refresh is right to
//!   stay behind — that commit removed a live person.
//!
//! A signed revocation proof carried in the commit would make the
//! witness independent of each receiver's freshness, at the price of a
//! proof format nobody issues yet (the socket's own note on
//! [`RevocationLookup`] says the same); check 5 is the witness every
//! device already has, so it is the one used.
//!
//! The witness reads the lookup registered on the identity provider the
//! rules were built with ([`AirdressMlsRules::sharing_revocation_with`]).
//! [`AirdressMlsRules::new`] shares none, so for rules built that way
//! the exception never holds.
//!
//! ## Why, and why it lives here rather than in the UI
//!
//! Requirements §11 OQ-4 settled the per-airdress layer. Allowing
//! cross-airdress removal hands a correspondent a denial-of-service
//! against another airdress's devices: Bob could quietly evict every one
//! of Alice's leaves and Alice would find herself unable to read her own
//! conversation. A correspondent's remedy for a peer's compromised
//! device is to **leave the conversation**, not to administer the
//! peer's device fleet. The per-person layer is the same argument one
//! level down: in a household group, owner and member are both members
//! of one airdress, and without it either could evict the other.
//!
//! Enforcement sits in the MLS rules, which is the only place it can
//! sit and mean anything:
//!
//! - a UI-only restriction is not a restriction — the proposal is
//!   constructed below the UI and a modified client skips it;
//! - `CommitDirection::Send` catches our own construction, so a bug in
//!   this crate cannot produce one either;
//! - `CommitDirection::Receive` catches a hand-crafted one, and it
//!   does so **without trusting the sender's label**: the sender's
//!   airdress and person are read out of the roster leaf the proposal's
//!   `Sender` points at, not out of anything the sender wrote.
//!
//! ## Send-side filtering versus receive-side rejection
//!
//! The [`mls_rs::MlsRules`] contract asks for invalid *by-reference* proposals
//! to be filtered out when preparing a commit rather than erroring,
//! and it is right: a peer who sends one bad by-reference proposal
//! would otherwise deadlock the group, because every subsequent commit
//! attempt would fail on the cached proposal. So a by-reference
//! refused `Remove` is dropped on `Send` and rejected on `Receive`. A
//! by-value one on `Send` is our own construction and is an error —
//! there is no deadlock to avoid and it means this crate has a bug.

use mls_rs::group::proposal::RemoveProposal;
use mls_rs::group::{Roster, Sender};
use mls_rs::identity::SigningIdentity;
use mls_rs::mls_rules::{
    CommitDirection, CommitOptions, CommitSource, DefaultMlsRules, EncryptionOptions,
    ProposalBundle, ProposalSource,
};
use mls_rs_core::error::IntoAnyError;
use mls_rs_core::group::GroupContext;

#[cfg(doc)]
use crate::credential::AirdressIdentity;
use crate::credential::{
    AirdressIdentityProvider, DeviceStatus, IdentityVersion, ParsedIdentity, RevocationLookup,
    parse_identity,
};

/// Why the rules refused a proposal set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlsRulesError {
    /// SPEC-061 FR-25: a member proposed the removal of a leaf that
    /// belongs to a different airdress.
    ///
    /// Carries both airdresses because the operator-side telemetry
    /// needs to say which pair it saw; neither is secret (both are
    /// public names) and neither is key material.
    CrossAirdressRemoval {
        /// The airdress whose member proposed the removal.
        by: String,
        /// The airdress of the leaf it tried to remove.
        target: String,
    },
    /// A member proposed the removal of a leaf of **another person of
    /// the same airdress** (SPEC-144 F-7), and the revocation witness
    /// did not hold: the target is the owner's device, or a household
    /// member's device this device's revocation lookup does not answer
    /// `Revoked` for.
    ///
    /// Carries the airdress only. Which persons were involved is not
    /// said: a `person_id` belongs in no log or metric label.
    CrossPersonRemoval {
        /// The airdress both leaves belong to.
        airdress: String,
    },
    /// A roster leaf carried a credential that could not be read.
    /// Distinct from the above so a malformed leaf is not reported as
    /// an attempted removal.
    UnreadableLeaf(String),
}

impl core::fmt::Display for MlsRulesError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            // One sentence, per the `credential.rs` discipline.
            Self::CrossAirdressRemoval { .. } => {
                f.write_str("only a device of the same airdress may remove that airdress's devices")
            }
            Self::CrossPersonRemoval { .. } => f.write_str(
                "only a person's own devices may remove that person's devices, unless the device is revoked",
            ),
            Self::UnreadableLeaf(msg) => write!(f, "unreadable group member: {msg}"),
        }
    }
}

impl std::error::Error for MlsRulesError {}

impl IntoAnyError for MlsRulesError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

/// What the removal rule needs to know about one leaf, read from its
/// credential.
struct Leaf {
    airdress: String,
    /// `None` for a legacy bare-string identity, which is the owner's
    /// by construction (it predates persons).
    version: Option<IdentityVersion>,
    /// The pin subject, computed only when a `v: 3` leaf is involved —
    /// see [`authorise_removal`].
    pin_subject: Result<String, String>,
    device_id: Option<String>,
}

impl Leaf {
    fn of(signing_identity: &SigningIdentity) -> Result<Self, MlsRulesError> {
        let basic = signing_identity.credential.as_basic().ok_or_else(|| {
            MlsRulesError::UnreadableLeaf("credential is not a basic credential".to_owned())
        })?;
        match parse_identity(&basic.identifier).map_err(MlsRulesError::UnreadableLeaf)? {
            ParsedIdentity::Structured(identity) => Ok(Self {
                pin_subject: identity.pin_subject().map_err(|e| e.to_string()),
                device_id: identity.device_id().map(str::to_owned),
                version: Some(identity.version),
                airdress: identity.airdress,
            }),
            ParsedIdentity::Legacy(airdress) => Ok(Self {
                pin_subject: Ok(airdress.clone()),
                device_id: None,
                version: None,
                airdress,
            }),
        }
    }

    fn is_person(&self) -> bool {
        self.version == Some(IdentityVersion::V3)
    }

    fn pin_subject(&self) -> Result<&str, MlsRulesError> {
        self.pin_subject
            .as_deref()
            .map_err(|e| MlsRulesError::UnreadableLeaf(e.clone()))
    }
}

/// The leaf at `index`, or an error naming why it could not be read.
fn leaf_at(roster: &Roster<'_>, index: u32) -> Result<Leaf, MlsRulesError> {
    let member = roster
        .member_with_index(index)
        .map_err(|e| MlsRulesError::UnreadableLeaf(e.to_string()))?;
    Leaf::of(member.signing_identity())
}

/// The leaf that authored a proposal, given its `Sender` and the source
/// of the commit being prepared or processed.
///
/// Read from the roster, never from the proposal body — a sender that
/// could name its own airdress or person could name someone else's.
fn proposer_leaf(
    sender: Sender,
    source: &CommitSource,
    roster: &Roster<'_>,
) -> Result<Option<Leaf>, MlsRulesError> {
    match sender {
        Sender::Member(index) => leaf_at(roster, index).map(Some),
        // A NewMember cannot propose Remove under RFC 9420's own
        // rules; mls-rs rejects it downstream. Nothing to decide here.
        Sender::NewMemberProposal | Sender::NewMemberCommit => match source {
            CommitSource::NewMember(identity) => Leaf::of(identity).map(Some),
            CommitSource::ExistingMember(member) => Leaf::of(member.signing_identity()).map(Some),
        },
        // External senders are excluded by SPEC-061 §9; if one ever
        // appears, it has no airdress and no standing to remove. The
        // wildcard catches any future `Sender` variant the same way,
        // which is the fail-closed direction.
        _ => Ok(None),
    }
}

/// The removal rule itself, for one proposer and one target.
///
/// Order matters and is the module's: airdress first (unchanged), then
/// — only when a `v: 3` leaf is on either side — pin subject, then the
/// revocation witness for a `v: 3` target.
fn authorise_removal(
    by: &Leaf,
    target: &Leaf,
    revocation: Option<&dyn RevocationLookup>,
) -> Result<(), MlsRulesError> {
    if by.airdress != target.airdress {
        return Err(MlsRulesError::CrossAirdressRemoval {
            by: by.airdress.clone(),
            target: target.airdress.clone(),
        });
    }
    // No person on either side: the airdress rule was the whole rule,
    // and `v: 1`/`v: 2`/legacy behaviour is exactly what it was.
    if !by.is_person() && !target.is_person() {
        return Ok(());
    }
    if by.pin_subject()? == target.pin_subject()? {
        return Ok(());
    }
    if target.is_person() && revocation_witness(target, revocation) {
        return Ok(());
    }
    Err(MlsRulesError::CrossPersonRemoval {
        airdress: target.airdress.clone(),
    })
}

/// Whether this device's check-5 lookup answers `Revoked` for the
/// target's `device_id`. Every other outcome — `Active`, no answer, no
/// lookup, no `device_id` — is "no witness".
fn revocation_witness(target: &Leaf, revocation: Option<&dyn RevocationLookup>) -> bool {
    let (Some(revocation), Some(device_id)) = (revocation, target.device_id.as_deref()) else {
        return false;
    };
    !device_id.is_empty() && revocation.device_status(device_id) == Some(DeviceStatus::Revoked)
}

/// [`authorise_removal`] for two signing identities: the engine's early
/// refusal in `propose_remove`, so it cannot drift from what the rules
/// enforce.
pub(crate) fn check_removal(
    by: &SigningIdentity,
    target: &SigningIdentity,
    revocation: Option<&dyn RevocationLookup>,
) -> Result<(), MlsRulesError> {
    authorise_removal(&Leaf::of(by)?, &Leaf::of(target)?, revocation)
}

/// [`DefaultMlsRules`] plus the removal rule above.
///
/// Everything else — commit options, encryption options — is
/// `DefaultMlsRules`' answer verbatim. Both engines use this type, so
/// the rule cannot be a function of which binary ran; two engines that
/// disagreed about which proposals are legal would fork the group.
#[derive(Debug, Clone, Default)]
pub struct AirdressMlsRules {
    inner: DefaultMlsRules,
    /// Where the revocation witness is read: the identity provider
    /// whose check-5 lookup the host registers. `None` means no witness
    /// ever holds.
    revocation_source: Option<AirdressIdentityProvider>,
}

impl AirdressMlsRules {
    /// The rules, wrapping mls-rs's defaults, with **no** revocation
    /// witness: another person's leaf is never removable through rules
    /// built this way, revoked or not. A host whose devices take part
    /// in household groups uses [`Self::sharing_revocation_with`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The rules, reading the revocation witness from `provider`'s
    /// check-5 lookup — whatever the host registers on it, now or
    /// later ([`AirdressIdentityProvider::set_revocation_lookup`]).
    /// Pass the same provider the client validates leaves with, so the
    /// device that refuses a revoked leaf's credential is the device
    /// that admits its removal.
    #[must_use]
    pub fn sharing_revocation_with(provider: &AirdressIdentityProvider) -> Self {
        Self {
            inner: DefaultMlsRules::default(),
            revocation_source: Some(provider.clone()),
        }
    }

    fn revocation(&self) -> Option<std::sync::Arc<dyn RevocationLookup>> {
        self.revocation_source
            .as_ref()
            .and_then(AirdressIdentityProvider::registered_revocation_lookup)
    }
}

impl mls_rs::MlsRules for AirdressMlsRules {
    type Error = MlsRulesError;

    fn filter_proposals(
        &self,
        direction: CommitDirection,
        source: CommitSource,
        current_roster: &Roster<'_>,
        current_context: &GroupContext,
        mut proposals: ProposalBundle,
    ) -> Result<ProposalBundle, Self::Error> {
        let revocation = self.revocation();
        proposals.retain_by_type::<RemoveProposal, _, Self::Error>(|info| {
            let target = leaf_at(current_roster, info.proposal.to_remove())?;
            let Some(by) = proposer_leaf(*info.sender(), &source, current_roster)? else {
                // No standing to remove anything.
                return match direction {
                    CommitDirection::Send => Ok(false),
                    CommitDirection::Receive => Err(MlsRulesError::CrossAirdressRemoval {
                        by: "<external>".to_owned(),
                        target: target.airdress,
                    }),
                };
            };
            match authorise_removal(&by, &target, revocation.as_deref()) {
                Ok(()) => Ok(true),
                Err(refusal @ MlsRulesError::UnreadableLeaf(_)) => Err(refusal),
                Err(refusal) => match (direction, info.source()) {
                    // Drop rather than error, so one hostile by-reference
                    // proposal cannot deadlock every future commit.
                    (CommitDirection::Send, ProposalSource::ByReference(_)) => Ok(false),
                    _ => Err(refusal),
                },
            }
        })?;

        self.inner
            .filter_proposals(
                direction,
                source,
                current_roster,
                current_context,
                proposals,
            )
            .map_err(|e: core::convert::Infallible| match e {})
    }

    fn commit_options(
        &self,
        new_roster: &Roster<'_>,
        new_context: &GroupContext,
        proposals: &ProposalBundle,
    ) -> Result<CommitOptions, Self::Error> {
        self.inner
            .commit_options(new_roster, new_context, proposals)
            .map_err(|e: core::convert::Infallible| match e {})
    }

    fn encryption_options(
        &self,
        current_roster: &Roster<'_>,
        current_context: &GroupContext,
    ) -> Result<EncryptionOptions, Self::Error> {
        self.inner
            .encryption_options(current_roster, current_context)
            .map_err(|e: core::convert::Infallible| match e {})
    }
}

#[cfg(test)]
mod tests {
    //! The removal rule, twice: as a function over credentials (every
    //! combination, cheaply), and through real engines in one household
    //! group (send side, receive side, and the commit that reaches every
    //! peer).

    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    use ed25519_dalek::SigningKey;
    use mls_rs::identity::SigningIdentity;
    use mls_rs::identity::basic::BasicCredential;
    use mls_rs_core::crypto::SignaturePublicKey;

    use super::{MlsRulesError, check_removal};
    use crate::credential::test_support::{
        signed_delegation_json, signed_delegation_json_v2, signed_delegation_json_v3,
    };
    use crate::credential::{AirdressIdentity, DeviceStatus, RevocationLookup};
    use crate::engine::MlsEngine;

    const HOME: &str = "home.test";
    const ELSEWHERE: &str = "elsewhere.test";
    const EXPIRES: &str = "2099-01-01T00:00:00Z";
    const PERSON_A: &str = "0b6f2c1e-0000-4000-8000-00000000000a";
    const PERSON_B: &str = "0b6f2c1e-0000-4000-8000-00000000000b";

    /// Who a device belongs to.
    #[derive(Clone, Copy)]
    enum Holder {
        /// The owner of `airdress`: a `v: 2` leaf.
        Owner(&'static str),
        /// A household member of [`HOME`]: a `v: 3` leaf.
        Person(&'static str),
    }

    fn delegation(holder: Holder, root: &SigningKey, session: &[u8; 32], device: &str) -> String {
        match holder {
            Holder::Owner(airdress) => {
                signed_delegation_json_v2(root, airdress, session, device, EXPIRES)
            }
            Holder::Person(person) => {
                signed_delegation_json_v3(root, HOME, person, session, device, EXPIRES)
            }
        }
    }

    const fn airdress(holder: Holder) -> &'static str {
        match holder {
            Holder::Owner(airdress) => airdress,
            Holder::Person(_) => HOME,
        }
    }

    // -----------------------------------------------------------------
    // The rule as a function
    // -----------------------------------------------------------------

    fn identity(holder: Holder, device: &str) -> SigningIdentity {
        let root = SigningKey::from_bytes(&[3u8; 32]);
        let json = delegation(holder, &root, &[5u8; 32], device);
        let serde_json::Value::Object(map) = serde_json::from_str(&json).unwrap() else {
            panic!("delegation is an object")
        };
        let identity = AirdressIdentity::from_delegation(
            airdress(holder).to_owned(),
            root.verifying_key().to_bytes(),
            map,
        );
        SigningIdentity::new(
            BasicCredential::new(identity.to_identity_bytes().unwrap()).into_credential(),
            SignaturePublicKey::from(vec![5u8; 32]),
        )
    }

    fn legacy(airdress: &str) -> SigningIdentity {
        SigningIdentity::new(
            BasicCredential::new(airdress.as_bytes().to_vec()).into_credential(),
            SignaturePublicKey::from(vec![5u8; 32]),
        )
    }

    fn revoked(devices: &'static [&'static str]) -> impl RevocationLookup {
        move |d: &str| {
            Some(if devices.contains(&d) {
                DeviceStatus::Revoked
            } else {
                DeviceStatus::Active
            })
        }
    }

    fn is_cross_person(r: &Result<(), MlsRulesError>) -> bool {
        matches!(r, Err(MlsRulesError::CrossPersonRemoval { airdress }) if airdress == HOME)
    }

    #[test]
    fn a_person_removes_their_own_devices() {
        let owner = Holder::Owner(HOME);
        let a = Holder::Person(PERSON_A);
        assert_eq!(
            check_removal(&identity(owner, "o1"), &identity(owner, "o2"), None),
            Ok(())
        );
        assert_eq!(
            check_removal(&identity(a, "a1"), &identity(a, "a2"), None),
            Ok(())
        );
    }

    #[test]
    fn another_persons_live_device_is_refused_both_ways() {
        let owner = Holder::Owner(HOME);
        let a = Holder::Person(PERSON_A);
        let b = Holder::Person(PERSON_B);
        let live = revoked(&[]);
        // Member removes an owner leaf; owner removes a live member
        // leaf; member removes another member's live leaf.
        for (by, target) in [
            (identity(a, "a1"), identity(owner, "o1")),
            (identity(owner, "o1"), identity(b, "b1")),
            (identity(a, "a1"), identity(b, "b1")),
        ] {
            assert!(is_cross_person(&check_removal(&by, &target, Some(&live))));
            assert!(is_cross_person(&check_removal(&by, &target, None)));
        }
    }

    #[test]
    fn a_revoked_member_device_is_removable_by_any_peer_of_the_airdress() {
        let owner = Holder::Owner(HOME);
        let a = Holder::Person(PERSON_A);
        let b = Holder::Person(PERSON_B);
        let witness = revoked(&["b1"]);
        for by in [identity(owner, "o1"), identity(a, "a1")] {
            assert_eq!(
                check_removal(&by, &identity(b, "b1"), Some(&witness)),
                Ok(())
            );
            // Only the device the lookup names: b2 is live.
            assert!(is_cross_person(&check_removal(
                &by,
                &identity(b, "b2"),
                Some(&witness)
            )));
        }
    }

    #[test]
    fn a_member_never_removes_an_owner_device_even_a_revoked_one() {
        let owner = Holder::Owner(HOME);
        let a = Holder::Person(PERSON_A);
        let witness = revoked(&["o2"]);
        assert!(is_cross_person(&check_removal(
            &identity(a, "a1"),
            &identity(owner, "o2"),
            Some(&witness)
        )));
        // The owner's own other device removes it, under the plain rule.
        assert_eq!(
            check_removal(
                &identity(owner, "o1"),
                &identity(owner, "o2"),
                Some(&witness)
            ),
            Ok(())
        );
    }

    #[test]
    fn no_answer_is_no_witness() {
        let owner = Holder::Owner(HOME);
        let b = Holder::Person(PERSON_B);
        let unknown = |_: &str| -> Option<DeviceStatus> { None };
        assert!(is_cross_person(&check_removal(
            &identity(owner, "o1"),
            &identity(b, "b1"),
            Some(&unknown)
        )));
    }

    #[test]
    fn the_revoked_exception_never_crosses_an_airdress() {
        let stranger = Holder::Owner(ELSEWHERE);
        let b = Holder::Person(PERSON_B);
        let witness = revoked(&["b1"]);
        assert_eq!(
            check_removal(
                &identity(stranger, "x1"),
                &identity(b, "b1"),
                Some(&witness)
            ),
            Err(MlsRulesError::CrossAirdressRemoval {
                by: ELSEWHERE.to_owned(),
                target: HOME.to_owned(),
            })
        );
    }

    /// `v: 1`, `v: 2` and legacy leaves: the airdress rule is the whole
    /// rule, with or without a lookup, revoked or not.
    #[test]
    fn without_a_person_leaf_the_rule_is_per_airdress_as_before() {
        let owner = Holder::Owner(HOME);
        let stranger = Holder::Owner(ELSEWHERE);
        let witness = revoked(&["o2", "x1"]);
        let root = SigningKey::from_bytes(&[3u8; 32]);
        let v1_json = signed_delegation_json(&root, HOME, &[5u8; 32]);
        let serde_json::Value::Object(map) = serde_json::from_str(&v1_json).unwrap() else {
            panic!()
        };
        let v1 = SigningIdentity::new(
            BasicCredential::new(
                AirdressIdentity::from_delegation(
                    HOME.to_owned(),
                    root.verifying_key().to_bytes(),
                    map,
                )
                .to_identity_bytes()
                .unwrap(),
            )
            .into_credential(),
            SignaturePublicKey::from(vec![5u8; 32]),
        );
        for lookup in [None, Some(&witness as &dyn RevocationLookup)] {
            assert_eq!(
                check_removal(&identity(owner, "o1"), &identity(owner, "o2"), lookup),
                Ok(())
            );
            assert_eq!(check_removal(&v1, &identity(owner, "o2"), lookup), Ok(()));
            assert_eq!(check_removal(&legacy(HOME), &v1, lookup), Ok(()));
            assert_eq!(
                check_removal(&identity(owner, "o1"), &identity(stranger, "x1"), lookup),
                Err(MlsRulesError::CrossAirdressRemoval {
                    by: HOME.to_owned(),
                    target: ELSEWHERE.to_owned(),
                })
            );
            assert_eq!(
                check_removal(&legacy(ELSEWHERE), &legacy(HOME), lookup),
                Err(MlsRulesError::CrossAirdressRemoval {
                    by: ELSEWHERE.to_owned(),
                    target: HOME.to_owned(),
                })
            );
        }
    }

    // -----------------------------------------------------------------
    // Through engines: one household group
    // -----------------------------------------------------------------

    /// One device: its engine, its own view of which devices are
    /// revoked (what its host's check-5 lookup answers), and the state
    /// directory that must outlive it.
    struct Device {
        name: &'static str,
        engine: MlsEngine,
        revoked: Arc<Mutex<HashSet<String>>>,
        _dir: tempfile::TempDir,
    }

    impl Device {
        fn new(holder: Holder, name: &'static str, seed: u8) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let root = SigningKey::from_bytes(&[seed.wrapping_add(100); 32]);
            let seed = [seed; 32];
            let session = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
            let engine = MlsEngine::from_seed(
                airdress(holder),
                &seed,
                &root.verifying_key().to_bytes(),
                &delegation(holder, &root, &session, name),
                dir.path().to_str().unwrap(),
                &[77u8; 32],
            )
            .unwrap();
            let revoked = Arc::new(Mutex::new(HashSet::new()));
            let view = Arc::clone(&revoked);
            engine.set_revocation_lookup(Arc::new(move |d: &str| {
                Some(if view.lock().unwrap().contains(d) {
                    DeviceStatus::Revoked
                } else {
                    DeviceStatus::Active
                })
            }));
            Self {
                name,
                engine,
                revoked,
                _dir: dir,
            }
        }

        /// This device's host learns that `device` is revoked.
        fn learns_revoked(&self, device: &str) {
            self.revoked.lock().unwrap().insert(device.to_owned());
        }
    }

    /// A group founded by `devices[0]`, every other device added one
    /// commit at a time.
    fn group(devices: &mut [Device]) -> Vec<u8> {
        let (founder, rest) = devices.split_first_mut().unwrap();
        let group_id = founder.engine.start_group_solo(b"hi", "").unwrap().group_id;
        for i in 0..rest.len() {
            let kp = rest[i].engine.generate_key_package().unwrap();
            founder.engine.propose_add(&group_id, &kp).unwrap();
            let outcome = founder.engine.commit_pending(&group_id).unwrap();
            founder.engine.confirm_commit(&group_id).unwrap();
            for member in &mut rest[..i] {
                member
                    .engine
                    .process_commit(&group_id, &outcome.commit)
                    .unwrap();
            }
            rest[i]
                .engine
                .process_welcome(&outcome.welcome.unwrap())
                .unwrap();
        }
        group_id
    }

    fn index_of(devices: &[Device], group_id: &[u8], name: &str) -> u32 {
        let suffix = [&[0x1F_u8][..], name.as_bytes()].concat();
        devices[0]
            .engine
            .group_members(group_id)
            .unwrap()
            .into_iter()
            .find(|m| m.identity.ends_with(&suffix))
            .unwrap_or_else(|| panic!("{name} is not in the group"))
            .index
    }

    fn device<'a>(devices: &'a mut [Device], name: &str) -> &'a mut Device {
        devices.iter_mut().find(|d| d.name == name).unwrap()
    }

    /// `by` removes `target`, and every other device but the target
    /// applies the commit. Returns the commit for further use.
    fn remove(devices: &mut [Device], group_id: &[u8], by: &str, target: &str) -> Vec<u8> {
        let index = index_of(devices, group_id, target);
        let committer = device(devices, by);
        committer.engine.propose_remove(group_id, index).unwrap();
        let commit = committer.engine.commit_pending(group_id).unwrap().commit;
        committer.engine.confirm_commit(group_id).unwrap();
        for peer in devices.iter_mut().filter(|d| d.name != by) {
            let outcome = peer.engine.process_commit(group_id, &commit).unwrap();
            assert_eq!(outcome.self_removed, peer.name == target, "{}", peer.name);
        }
        commit
    }

    fn household() -> (Vec<Device>, Vec<u8>) {
        let mut devices = vec![
            Device::new(Holder::Owner(HOME), "o1", 11),
            Device::new(Holder::Owner(HOME), "o2", 12),
            Device::new(Holder::Person(PERSON_A), "a1", 13),
            Device::new(Holder::Person(PERSON_A), "a2", 14),
            Device::new(Holder::Person(PERSON_B), "b1", 15),
        ];
        let group_id = group(&mut devices);
        (devices, group_id)
    }

    const CROSS_PERSON: &str = "only a person's own devices may remove that person's devices, unless the device is revoked";

    #[test]
    fn in_a_household_group_the_owner_removes_its_own_device() {
        let (mut devices, group_id) = household();
        remove(&mut devices, &group_id, "o1", "o2");
    }

    #[test]
    fn in_a_household_group_a_member_removes_their_own_device() {
        let (mut devices, group_id) = household();
        remove(&mut devices, &group_id, "a1", "a2");
    }

    #[test]
    fn in_a_household_group_a_member_cannot_remove_an_owner_device() {
        let (mut devices, group_id) = household();
        let index = index_of(&devices, &group_id, "o2");
        // Even with its own host claiming the owner device is revoked.
        let a1 = device(&mut devices, "a1");
        a1.learns_revoked("o2");
        assert_eq!(
            a1.engine.propose_remove(&group_id, index),
            Err(CROSS_PERSON.to_owned())
        );
    }

    #[test]
    fn in_a_household_group_the_owner_cannot_remove_a_live_member_device() {
        let (mut devices, group_id) = household();
        let index = index_of(&devices, &group_id, "b1");
        assert_eq!(
            device(&mut devices, "o1")
                .engine
                .propose_remove(&group_id, index),
            Err(CROSS_PERSON.to_owned())
        );
    }

    #[test]
    fn in_a_household_group_any_peer_removes_a_revoked_member_device() {
        // The operator revoked b1 and every device has heard.
        for committer in ["o1", "a1"] {
            let (mut devices, group_id) = household();
            for d in &devices {
                d.learns_revoked("b1");
            }
            remove(&mut devices, &group_id, committer, "b1");
        }
    }

    /// The witness is each receiver's own lookup, not the committer's
    /// word: a commit removing a device the receiver holds live is
    /// refused and persists nothing; once the receiver's host learns of
    /// the revocation, the same commit applies.
    #[test]
    fn the_revoked_exception_cannot_be_turned_against_a_live_person() {
        let (mut devices, group_id) = household();
        let index = index_of(&devices, &group_id, "b1");
        let o1 = device(&mut devices, "o1");
        o1.learns_revoked("b1"); // Stale, or a lie: nobody else agrees.
        o1.engine.propose_remove(&group_id, index).unwrap();
        let commit = o1.engine.commit_pending(&group_id).unwrap().commit;
        o1.engine.confirm_commit(&group_id).unwrap();

        let a1 = device(&mut devices, "a1");
        let epoch = a1.engine.group_epoch(&group_id).unwrap();
        let err = a1
            .engine
            .process_commit(&group_id, &commit)
            .expect_err("a live person's device must not be removable on one device's say-so")
            .to_string();
        assert!(err.contains(CROSS_PERSON), "{err}");
        assert_eq!(a1.engine.group_epoch(&group_id), Some(epoch));

        // The receiver's host refreshes its revocation state: the
        // operator did revoke it after all. The same commit applies.
        a1.learns_revoked("b1");
        let outcome = a1.engine.process_commit(&group_id, &commit).unwrap();
        assert_eq!(outcome.removed.len(), 1);
    }

    /// A `v: 2` group across two airdresses, as before persons existed:
    /// the owner removes its own device, and the correspondent cannot.
    #[test]
    fn a_v2_group_removes_per_airdress_as_before() {
        let mut devices = vec![
            Device::new(Holder::Owner(HOME), "o1", 21),
            Device::new(Holder::Owner(HOME), "o2", 22),
            Device::new(Holder::Owner(ELSEWHERE), "x1", 23),
        ];
        let group_id = group(&mut devices);
        let index = index_of(&devices, &group_id, "o2");
        let x1 = device(&mut devices, "x1");
        x1.learns_revoked("o2");
        assert_eq!(
            x1.engine.propose_remove(&group_id, index),
            Err("only a device of the same airdress may remove that airdress's devices".to_owned())
        );
        remove(&mut devices, &group_id, "o1", "o2");
    }
}
