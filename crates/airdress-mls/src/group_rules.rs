//! The rules of a group conversation (SPEC-145 design D-5).
//!
//! They apply to a group whose context carries the group extensions
//! ([`crate::group_context`]) and to no other: a one-to-one or self
//! conversation keeps [`crate::rules`]' removal rule exactly as it was.
//! Every client runs the same rules over the same state, on every commit it
//! builds or processes, so every honest client reaches the same verdict. No
//! operator can check any of this — it cannot read a commit.
//!
//! | Proposal | Allowed when the proposer… |
//! |---|---|
//! | `Add` of a new person | is an admin, or the policy lets members add |
//! | `Add` of a device of a person already in | is that person (FR-11) |
//! | `Remove` | is an admin (F-1: across airdresses), or is the leaf's own person — which covers a self-`Remove` committed by anyone (D-8) — or holds the revocation witness [`crate::rules`] already admits |
//! | a change to `policy` | is an admin |
//! | a change to `profile` | is an admin, or the policy lets members edit it |
//! | a change to `sequencer` | is an admin, or the commit removes a whole person (D-12's move) |
//! | a change to `roles` | is an admin, or the change is exactly [`forced_roles`] |
//!
//! | a change to any other context extension | is an admin |
//! | `Update` | — (a leaf's own key rotation, as MLS defines it) |
//! | anything else (`ReInit`, `PreSharedKey`, `ExternalInit`, custom) | is refused: nothing in a group conversation uses them |
//!
//! And after every commit: at least one admin is still in the group (FR-16),
//! and no admin the roles name joins or leaves the group while named. A
//! commit that removes an admin therefore has to carry the roles without
//! them, one that adds back a person the roles still name has to carry the
//! roles without them too, and one that removes the last admin the forced
//! promotion, whoever commits it. An admin the roles name who was already
//! gone before the commit (roles an earlier release left behind) is
//! tolerated, and dropped by the next roles change. An honest
//! committing device adds that change itself when its commit needs it
//! ([`forced_roles`]), so a leave or a removal never wedges the group. A
//! committing device also refuses to grow the group past
//! [`GROUP_MAX_PERSONS`] persons or [`GROUP_LEAF_CAP`] devices (D-11); a
//! group already past a cap still takes every commit that does not grow it.
//!
//! Authority is read from the roster leaf a proposal's `Sender` points at,
//! never from anything the proposer wrote. As in [`crate::rules`], a refused
//! by-reference proposal is dropped when this device commits (so one hostile
//! proposal cannot wedge the group) and is an error everywhere else.
//!
//! ## What a refusal costs
//!
//! The sequencer grants epochs it cannot read, so a rule-breaking commit
//! from a modified client is still granted its epoch. Honest clients refuse
//! it and stay at the epoch before it; the group's admins re-found it
//! without the committer (design D-5, D-13). That is the price of a
//! delivery service that never sees a commit.

use std::collections::BTreeSet;

use mls_rs::ExtensionList;
use mls_rs::group::proposal::{AddProposal, BorrowedProposal, Proposal, RemoveProposal};
use mls_rs::group::{Roster, Sender};
use mls_rs::mls_rules::{CommitDirection, CommitSource, ProposalBundle, ProposalSource};

use crate::credential::RevocationLookup;
use crate::group_context::{
    GROUP_EXTENSION_TYPES, GROUP_LEAF_CAP, GROUP_MAX_PERSONS, GroupExtensions, forced_roles,
};
use crate::rules::{Leaf, MlsRulesError, authorise_removal, leaf_at, proposer_leaf};

/// Which group rule a proposal set broke. The sentence is for a journal;
/// the variant is what a caller branches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroupRule {
    /// A member who is not an admin added a person while the policy
    /// lets only admins add.
    AddPerson,
    /// Somebody added a device of a person other than themselves.
    AddDevice,
    /// A member who is not an admin removed another person's device.
    RemoveOther,
    /// A member who is not an admin changed the roles other than by the
    /// forced promotion, or an admin left them malformed.
    ChangeRoles,
    /// A member who is not an admin changed the policy.
    ChangePolicy,
    /// A member who is not an admin changed the title or picture while
    /// the policy lets only admins.
    ChangeProfile,
    /// A member who is not an admin moved the sequencer outside a commit
    /// that removes a person.
    ChangeSequencer,
    /// The commit would leave the group with no admin.
    NoAdminLeft,
    /// The commit would take the group past its person cap.
    TooManyPersons,
    /// The proposed group extensions do not parse, or drop the group.
    MalformedExtensions,
    /// The roles would name an admin who is not in the group.
    AdminNotInGroup,
    /// A member who is not an admin changed a context extension outside
    /// the four group extensions.
    ChangeOtherExtensions,
    /// A kind of proposal this conversation does not take (`ReInit`,
    /// `PreSharedKey`, `ExternalInit`, a custom proposal).
    UnsupportedProposal,
    /// A conversation founded without the group extensions (one-to-one,
    /// self, household) was given some. Only a group founded as one is a
    /// group conversation; nothing turns another conversation into one.
    NotAGroup,
}

impl core::fmt::Display for GroupRule {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::AddPerson => "only an admin may add a person to this group",
            Self::AddDevice => "only a person may add their own devices to a group",
            Self::RemoveOther => "only an admin may remove another person from a group",
            Self::ChangeRoles => "only an admin may change a group's admins",
            Self::ChangePolicy => "only an admin may change a group's settings",
            Self::ChangeProfile => "only an admin may change this group's name and picture",
            Self::ChangeSequencer => "only an admin may move a group's sequencer",
            Self::NoAdminLeft => "a group must keep at least one admin",
            Self::TooManyPersons => "that would make the group too big",
            Self::MalformedExtensions => "the group's settings in this change are unreadable",
            Self::AdminNotInGroup => "a group's admins must all be in the group",
            Self::ChangeOtherExtensions => "only an admin may change a group's other settings",
            Self::UnsupportedProposal => "this conversation does not take that kind of change",
            Self::NotAGroup => "this conversation is not a group and cannot take on group settings",
        })
    }
}

#[cfg(test)]
thread_local! {
    /// The release before the admin-membership rule, for the tests: while
    /// set, this thread's engines neither add nor require the roles change
    /// that rule asks for, on either side.
    pub(crate) static ROLES_UNCHECKED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
thread_local! {
    /// A modified client, for the tests: while set, this thread's engines
    /// build commits without the group rules, exactly as a client with the
    /// checks patched out would. Receivers are unaffected.
    pub(crate) static SEND_UNCHECKED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The cap the committing device holds, overridable by tests.
#[cfg(not(test))]
const fn person_cap() -> usize {
    GROUP_MAX_PERSONS
}

#[cfg(test)]
thread_local! {
    pub(crate) static PERSON_CAP: std::cell::Cell<usize> = const { std::cell::Cell::new(GROUP_MAX_PERSONS) };
}

#[cfg(test)]
fn person_cap() -> usize {
    PERSON_CAP.with(std::cell::Cell::get)
}

/// The leaf cap the committing device holds, overridable by tests.
#[cfg(not(test))]
const fn leaf_cap() -> usize {
    GROUP_LEAF_CAP
}

#[cfg(test)]
thread_local! {
    pub(crate) static LEAF_CAP: std::cell::Cell<usize> = const { std::cell::Cell::new(GROUP_LEAF_CAP) };
}

#[cfg(test)]
fn leaf_cap() -> usize {
    LEAF_CAP.with(std::cell::Cell::get)
}

/// One group's rules, read from the context the commit is made in.
pub(crate) struct GroupView<'a> {
    current: GroupExtensions,
    /// The whole context extension list, group extensions included.
    context: &'a ExtensionList,
    roster: &'a Roster<'a>,
    /// The persons in the group before the commit, by pin subject.
    before: BTreeSet<String>,
}

impl<'a> GroupView<'a> {
    /// `None` for a context that is not a group conversation.
    pub(crate) fn of(
        roster: &'a Roster<'a>,
        context_extensions: &'a ExtensionList,
    ) -> Result<Option<Self>, MlsRulesError> {
        let Some(current) = GroupExtensions::from_list(context_extensions)
            .map_err(|_unreadable| MlsRulesError::Group(GroupRule::MalformedExtensions))?
        else {
            return Ok(None);
        };
        let mut before = BTreeSet::new();
        for member in roster.members_iter() {
            before.insert(
                Leaf::of(member.signing_identity())?
                    .pin_subject()?
                    .to_owned(),
            );
        }
        Ok(Some(Self {
            current,
            context: context_extensions,
            roster,
            before,
        }))
    }

    fn is_admin(&self, leaf: &Leaf) -> Result<bool, MlsRulesError> {
        let pin = leaf.pin_subject()?;
        Ok(self.current.roles.admins.iter().any(|a| a == pin))
    }

    /// An admin the current roles name who is not in the group: what a
    /// release before the admin-membership rule could leave behind.
    fn is_stale_admin(&self, person: &str) -> bool {
        self.current.roles.admins.iter().any(|a| a == person) && !self.before.contains(person)
    }

    /// [`forced_roles`] for `after`, from the current roles with their
    /// stale admins dropped first, so a person they name who is added back
    /// is a member and not an admin.
    fn forced_roles(
        &self,
        roles: &crate::group_context::GroupRoles,
        after: &[String],
    ) -> crate::group_context::GroupRoles {
        let mut kept = roles.clone();
        kept.admins.retain(|a| !self.is_stale_admin(a));
        forced_roles(&kept, after)
    }
}

/// The early refusal `propose_remove` makes in a group conversation, so it
/// cannot drift from what [`filter`] enforces: an admin removes anyone, a
/// person their own devices, and the revocation witness still holds.
///
/// # Errors
/// [`MlsRulesError::Group`] with [`GroupRule::RemoveOther`], or an
/// unreadable leaf.
pub(crate) fn check_removal(
    current: &GroupExtensions,
    by: &mls_rs::identity::SigningIdentity,
    target: &mls_rs::identity::SigningIdentity,
    revocation: Option<&dyn RevocationLookup>,
) -> Result<(), MlsRulesError> {
    let (by, target) = (Leaf::of(by)?, Leaf::of(target)?);
    let pin = by.pin_subject()?;
    if current.roles.admins.iter().any(|a| a == pin)
        || pin == target.pin_subject()?
        || authorise_removal(&by, &target, revocation).is_ok()
    {
        return Ok(());
    }
    Err(MlsRulesError::Group(GroupRule::RemoveOther))
}

/// Apply the group rules to a proposal set, keeping or refusing each
/// proposal, then check what the commit leaves behind.
///
/// # Errors
/// [`MlsRulesError::Group`] naming the rule, or an unreadable leaf.
pub(crate) fn filter(
    view: &GroupView<'_>,
    direction: CommitDirection,
    source: &CommitSource,
    proposals: &mut ProposalBundle,
    revocation: Option<&dyn RevocationLookup>,
) -> Result<(), MlsRulesError> {
    #[cfg(test)]
    if direction == CommitDirection::Send && SEND_UNCHECKED.with(std::cell::Cell::get) {
        return Ok(());
    }
    let roster = view.roster;

    // Proposal kinds the group rules do not name.
    refuse_unsupported(direction, proposals)?;

    // Removes.
    proposals.retain_by_type::<RemoveProposal, _, MlsRulesError>(|info| {
        let index = info.proposal.to_remove();
        let target = leaf_at(roster, index)?;
        let sender = *info.sender();
        let allowed = match proposer_leaf(sender, source, roster)? {
            None => false,
            Some(by) => {
                view.is_admin(&by)?
                    || by.pin_subject()? == target.pin_subject()?
                    || matches!(sender, Sender::Member(i) if i == index)
                    || authorise_removal(&by, &target, revocation).is_ok()
            }
        };
        keep_or_refuse(allowed, direction, info.source(), GroupRule::RemoveOther)
    })?;

    // Adds.
    let policy = view.current.policy;
    proposals.retain_by_type::<AddProposal, _, MlsRulesError>(|info| {
        let joining = Leaf::of(info.proposal.signing_identity())?;
        let joining_pin = joining.pin_subject()?.to_owned();
        let (allowed, rule) = match proposer_leaf(*info.sender(), source, roster)? {
            None => (false, GroupRule::AddPerson),
            Some(by) if view.before.contains(&joining_pin) => {
                (by.pin_subject()? == joining_pin, GroupRule::AddDevice)
            }
            Some(by) => (
                view.is_admin(&by)? || policy.members_may_add,
                GroupRule::AddPerson,
            ),
        };
        keep_or_refuse(allowed, direction, info.source(), rule)
    })?;

    // Who is in the group after the commit, in leaf order then add order.
    let removed: BTreeSet<u32> = proposals
        .remove_proposals()
        .iter()
        .map(|i| i.proposal.to_remove())
        .collect();
    let mut after: Vec<String> = Vec::new();
    for member in roster.members_iter() {
        if !removed.contains(&member.index) {
            push_unique(
                &mut after,
                Leaf::of(member.signing_identity())?.pin_subject()?,
            );
        }
    }
    for add in proposals.add_proposals() {
        push_unique(
            &mut after,
            Leaf::of(add.proposal.signing_identity())?.pin_subject()?,
        );
    }
    let removes_a_person = view.before.iter().any(|p| !after.contains(p));

    // The context change, if any.
    let mut roles_after = view.current.roles.clone();
    proposals.retain_by_type::<ExtensionList, _, MlsRulesError>(|info| {
        let Some(proposed) = GroupExtensions::from_list(&info.proposal).ok().flatten() else {
            return keep_or_refuse(
                false,
                direction,
                info.source(),
                GroupRule::MalformedExtensions,
            );
        };
        let admin = match proposer_leaf(*info.sender(), source, roster)? {
            Some(by) => view.is_admin(&by)?,
            None => false,
        };
        let verdict =
            context_change(view, &proposed, admin, &after, removes_a_person).and_then(|()| {
                if admin || others_unchanged(view.context, &info.proposal) {
                    Ok(())
                } else {
                    Err(GroupRule::ChangeOtherExtensions)
                }
            });
        match verdict {
            Ok(()) => {
                roles_after = proposed.roles;
                Ok(true)
            }
            Err(rule) => keep_or_refuse(false, direction, info.source(), rule),
        }
    })?;

    #[cfg(test)]
    let roles_unchecked = ROLES_UNCHECKED.with(std::cell::Cell::get);
    #[cfg(not(test))]
    let roles_unchecked = false;

    // A commit this device builds that removes a named admin, or adds back
    // a person the roles still name, carries the roles without them,
    // promoting when no admin is left (FR-16): the change every honest
    // committer is allowed to make.
    if direction == CommitDirection::Send
        && !roles_unchecked
        && !(has_admin(&roles_after, &after) && roles_hold(view, &roles_after, &after))
    {
        roles_after = add_forced_roles(view, source, proposals, &after, removes_a_person)?;
    }

    // FR-16: an admin stays, and no named admin joins or leaves.
    if !has_admin(&roles_after, &after) {
        return Err(MlsRulesError::Group(GroupRule::NoAdminLeft));
    }
    if !roles_unchecked && !roles_hold(view, &roles_after, &after) {
        return Err(MlsRulesError::Group(GroupRule::AdminNotInGroup));
    }
    // D-11: the committing device holds the caps, on a commit that grows
    // the group past them. A group already past a cap still takes a
    // removal, a key rotation or a settings change.
    if direction == CommitDirection::Send {
        let persons_grow = after.len() > view.before.len();
        if persons_grow && after.len() > person_cap() {
            return Err(MlsRulesError::Group(GroupRule::TooManyPersons));
        }
        // And the leaf cap, so the Welcome fits one envelope.
        let leaves_before = roster.members_iter().count();
        let leaves_after = leaves_before - removed.len() + proposals.add_proposals().len();
        if leaves_after > leaves_before && leaves_after > leaf_cap() {
            return Err(MlsRulesError::Group(GroupRule::TooManyPersons));
        }
    }
    Ok(())
}

/// Refuse every proposal kind the group rules do not name. `Update` is a
/// leaf's own key rotation and stays.
fn refuse_unsupported(
    direction: CommitDirection,
    proposals: &mut ProposalBundle,
) -> Result<(), MlsRulesError> {
    proposals.retain::<_, MlsRulesError>(|info| {
        let supported = !matches!(
            info.proposal,
            BorrowedProposal::ReInit(_)
                | BorrowedProposal::Psk(_)
                | BorrowedProposal::ExternalInit(_)
        );
        keep_or_refuse(
            supported,
            direction,
            info.source(),
            GroupRule::UnsupportedProposal,
        )
    })?;
    proposals.retain_custom::<_, MlsRulesError>(|info| {
        keep_or_refuse(
            false,
            direction,
            info.source(),
            GroupRule::UnsupportedProposal,
        )
    })
}

/// Whether an admin the roles name is among `after`.
fn has_admin(roles: &crate::group_context::GroupRoles, after: &[String]) -> bool {
    roles.admins.iter().any(|a| after.contains(a))
}

/// Whether every admin the roles name is among `after`, except a stale one
/// ([`GroupView::is_stale_admin`]), which must stay out: a named admin is
/// neither removed nor added back by a commit that keeps naming them.
fn roles_hold(
    view: &GroupView<'_>,
    roles: &crate::group_context::GroupRoles,
    after: &[String],
) -> bool {
    roles
        .admins
        .iter()
        .all(|a| after.contains(a) != view.is_stale_admin(a))
}

/// Replace the commit's context change, if any, with one whose roles are
/// [`forced_roles`] for `after`, proposed by value by the committer.
///
/// The base is the committer's own by-value change when it made one (its
/// title or picture edit stays), otherwise the current context; a
/// by-reference change from someone else is dropped, as any refused
/// by-reference proposal is on send. The result is held to the same rules
/// as any other context change.
fn add_forced_roles(
    view: &GroupView<'_>,
    source: &CommitSource,
    proposals: &mut ProposalBundle,
    after: &[String],
    removes_a_person: bool,
) -> Result<crate::group_context::GroupRoles, MlsRulesError> {
    let malformed = || MlsRulesError::Group(GroupRule::MalformedExtensions);
    let CommitSource::ExistingMember(committer) = source else {
        return Err(MlsRulesError::Group(GroupRule::NoAdminLeft));
    };
    let own = proposals
        .group_context_ext_proposals()
        .iter()
        .find(|p| p.is_by_value())
        .map(|p| p.proposal.clone());
    let base_list = own.unwrap_or_else(|| view.context.clone());
    let mut base = GroupExtensions::from_list(&base_list)
        .ok()
        .flatten()
        .ok_or_else(malformed)?;
    base.roles = view.forced_roles(&base.roles, after);
    let admin = view.is_admin(&Leaf::of(committer.signing_identity())?)?;
    context_change(view, &base, admin, after, removes_a_person).map_err(MlsRulesError::Group)?;
    let mut list = base_list;
    for extension in base.to_list().map_err(|_unreadable| malformed())?.iter() {
        list.set(extension.clone());
    }
    proposals.retain_by_type::<ExtensionList, _, MlsRulesError>(|_| Ok(false))?;
    proposals.add(
        Proposal::GroupContextExtensions(list),
        Sender::Member(committer.index),
        ProposalSource::ByValue,
    );
    Ok(base.roles)
}

/// Whether `proposed` keeps every context extension outside the group set
/// exactly as `current` has it.
fn others_unchanged(current: &ExtensionList, proposed: &ExtensionList) -> bool {
    let others = |list: &ExtensionList| {
        let mut v: Vec<_> = list
            .iter()
            .filter(|e| !GROUP_EXTENSION_TYPES.contains(&e.extension_type))
            .map(|e| (e.extension_type, e.extension_data.clone()))
            .collect();
        v.sort();
        v
    };
    others(current) == others(proposed)
}

/// Whether a proposed set of group extensions is a change this proposer
/// may make.
fn context_change(
    view: &GroupView<'_>,
    proposed: &GroupExtensions,
    admin: bool,
    after: &[String],
    removes_a_person: bool,
) -> Result<(), GroupRule> {
    let current = &view.current;
    if proposed.policy != current.policy && !admin {
        return Err(GroupRule::ChangePolicy);
    }
    if proposed.profile != current.profile && !admin && !current.policy.members_may_edit_profile {
        return Err(GroupRule::ChangeProfile);
    }
    if proposed.sequencer != current.sequencer && !admin && !removes_a_person {
        return Err(GroupRule::ChangeSequencer);
    }
    if proposed.roles != current.roles {
        let forced = view.forced_roles(&current.roles, after);
        if proposed.roles.join_order != forced.join_order {
            return Err(GroupRule::ChangeRoles);
        }
        let well_formed = proposed.roles.admins.iter().all(|a| after.contains(a));
        if !(if admin {
            well_formed
        } else {
            proposed.roles == forced
        }) {
            return Err(GroupRule::ChangeRoles);
        }
    }
    Ok(())
}

/// Keep an allowed proposal; drop a refused by-reference one this device
/// is committing; refuse everything else.
pub(crate) fn keep_or_refuse(
    allowed: bool,
    direction: CommitDirection,
    source: &ProposalSource,
    rule: GroupRule,
) -> Result<bool, MlsRulesError> {
    if allowed {
        return Ok(true);
    }
    match (direction, source) {
        (CommitDirection::Send, ProposalSource::ByReference(_)) => Ok(false),
        _ => Err(MlsRulesError::Group(rule)),
    }
}

fn push_unique(list: &mut Vec<String>, item: &str) {
    if !list.iter().any(|x| x == item) {
        list.push(item.to_owned());
    }
}

#[cfg(test)]
#[path = "group_rules_tests.rs"]
pub(crate) mod tests;
