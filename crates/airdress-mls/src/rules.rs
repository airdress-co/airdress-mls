//! Airdress MLS rules: cross-airdress removal is refused (SPEC-061
//! FR-25).
//!
//! ## The rule
//!
//! A member may propose `Remove` only for leaves under its **own**
//! airdress. Bob cannot evict one of Alice's devices.
//!
//! ## Why, and why it lives here rather than in the UI
//!
//! Requirements §11 OQ-4 settled this. Allowing cross-airdress removal
//! hands a correspondent a denial-of-service against another
//! airdress's devices: Bob could quietly evict every one of Alice's
//! leaves and Alice would find herself unable to read her own
//! conversation. A correspondent's remedy for a peer's compromised
//! device is to **leave the conversation**, not to administer the
//! peer's device fleet.
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
//!   airdress is read out of the roster leaf the proposal's `Sender`
//!   points at, not out of anything the sender wrote.
//!
//! ## Send-side filtering versus receive-side rejection
//!
//! The [`mls_rs::MlsRules`] contract asks for invalid *by-reference* proposals
//! to be filtered out when preparing a commit rather than erroring,
//! and it is right: a peer who sends one bad by-reference proposal
//! would otherwise deadlock the group, because every subsequent commit
//! attempt would fail on the cached proposal. So a by-reference
//! cross-airdress `Remove` is dropped on `Send` and rejected on
//! `Receive`. A by-value one on `Send` is our own construction and is
//! an error — there is no deadlock to avoid and it means this crate
//! has a bug.

use mls_rs::group::proposal::RemoveProposal;
use mls_rs::group::{Roster, Sender};
use mls_rs::mls_rules::{
    CommitDirection, CommitOptions, CommitSource, DefaultMlsRules, EncryptionOptions,
    ProposalBundle, ProposalSource,
};
use mls_rs_core::error::IntoAnyError;
use mls_rs_core::group::GroupContext;

use crate::credential::airdress_of;

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

/// The airdress owning the leaf at `index`, or an error naming why the
/// leaf could not be read.
fn airdress_at(roster: &Roster<'_>, index: u32) -> Result<String, MlsRulesError> {
    let member = roster
        .member_with_index(index)
        .map_err(|e| MlsRulesError::UnreadableLeaf(e.to_string()))?;
    airdress_of(member.signing_identity()).map_err(|e| MlsRulesError::UnreadableLeaf(e.to_string()))
}

/// The airdress that authored a proposal, given its `Sender` and the
/// source of the commit being prepared or processed.
///
/// Read from the roster, never from the proposal body — a sender that
/// could name its own airdress could name someone else's.
fn proposer_airdress(
    sender: Sender,
    source: &CommitSource,
    roster: &Roster<'_>,
) -> Result<Option<String>, MlsRulesError> {
    match sender {
        Sender::Member(index) => airdress_at(roster, index).map(Some),
        // A NewMember cannot propose Remove under RFC 9420's own
        // rules; mls-rs rejects it downstream. Nothing to decide here.
        Sender::NewMemberProposal | Sender::NewMemberCommit => match source {
            CommitSource::NewMember(identity) => airdress_of(identity)
                .map(Some)
                .map_err(|e| MlsRulesError::UnreadableLeaf(e.to_string())),
            CommitSource::ExistingMember(member) => airdress_of(member.signing_identity())
                .map(Some)
                .map_err(|e| MlsRulesError::UnreadableLeaf(e.to_string())),
        },
        // External senders are excluded by SPEC-061 §9; if one ever
        // appears, it has no airdress and no standing to remove. The
        // wildcard catches any future `Sender` variant the same way,
        // which is the fail-closed direction.
        _ => Ok(None),
    }
}

/// [`DefaultMlsRules`] plus SPEC-061 FR-25.
///
/// Everything else — commit options, encryption options — is
/// `DefaultMlsRules`' answer verbatim. Both engines use this type, so
/// the rule cannot be a function of which binary ran; two engines that
/// disagreed about which proposals are legal would fork the group.
#[derive(Debug, Clone, Default)]
pub struct AirdressMlsRules {
    inner: DefaultMlsRules,
}

impl AirdressMlsRules {
    /// The rules, wrapping mls-rs's defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
        proposals.retain_by_type::<RemoveProposal, _, Self::Error>(|info| {
            let Some(by) = proposer_airdress(*info.sender(), &source, current_roster)? else {
                // No standing to remove anything.
                return match direction {
                    CommitDirection::Send => Ok(false),
                    CommitDirection::Receive => Err(MlsRulesError::CrossAirdressRemoval {
                        by: "<external>".to_owned(),
                        target: airdress_at(current_roster, info.proposal.to_remove())?,
                    }),
                };
            };
            let target = airdress_at(current_roster, info.proposal.to_remove())?;
            if by == target {
                return Ok(true);
            }
            let refusal = MlsRulesError::CrossAirdressRemoval { by, target };
            match (direction, info.source()) {
                // Drop rather than error, so one hostile by-reference
                // proposal cannot deadlock every future commit.
                (CommitDirection::Send, ProposalSource::ByReference(_)) => Ok(false),
                _ => Err(refusal),
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
