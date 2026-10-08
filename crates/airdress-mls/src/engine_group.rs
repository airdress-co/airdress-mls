//! Group conversations on the engine (SPEC-145 design §3.3): create one
//! with its context extensions, read them, stage a change to them, propose
//! leaving, and read the roster by person.
//!
//! The rules every commit is held to live in [`crate::group_rules`] and run
//! inside `mls-rs`, so this module only builds and reads; it decides
//! nothing a modified client could skip.

use mls_rs::MlsMessage;

use super::{MlsEngine, StagedProposal};
use crate::group_context::{GROUP_EXTENSION_VERSION, GroupExtensions};
use crate::rules::Leaf;

/// One leaf of a group conversation, as the app groups leaves into persons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterEntry {
    /// Leaf index: what a `Remove` names.
    pub index: u32,
    /// The airdress the leaf belongs to.
    pub airdress: String,
    /// The person, by pin subject (SPEC-144): the bare airdress for its
    /// owner and for every `v: 2` leaf.
    pub pin_subject: String,
    /// The device, when the credential names one (`v: 2` and later).
    pub device_id: Option<String>,
    /// Whether this is the device asking.
    pub own: bool,
}

/// The epoch a message or commit was made in, read from its framing
/// without a key (design D-10): a device holds what is ahead of it.
///
/// # Errors
/// The bytes do not parse, or carry no epoch (a Welcome, a key package).
pub fn message_epoch(message: &[u8]) -> Result<u64, String> {
    MlsMessage::from_bytes(message)
        .map_err(|e| format!("bad message: {e}"))?
        .epoch()
        .ok_or_else(|| "this message carries no epoch in its framing".to_owned())
}

impl MlsEngine {
    /// Create a group conversation with this device as its only leaf and
    /// `extensions` in its context (FR-6 step 1). The members come in the
    /// first commit, through [`Self::propose_add`].
    ///
    /// The creator is the first admin and the first in the join order:
    /// `extensions.roles` must say exactly that.
    ///
    /// # Errors
    /// The extensions are malformed or do not name this device's person as
    /// the sole admin, or the group cannot be created or persisted.
    pub fn create_group_with_extensions(
        &mut self,
        extensions: &GroupExtensions,
    ) -> Result<Vec<u8>, String> {
        let own = self.own_pin_subject()?;
        if extensions.roles.admins != [own.clone()] || extensions.roles.join_order != [own] {
            return Err("a new group's creator is its only admin and first member".to_owned());
        }
        let mut group = self
            .client
            .create_group(
                extensions.to_list()?,
                mls_rs::ExtensionList::default(),
                None,
            )
            .map_err(|e| format!("create group: {e}"))?;
        group
            .write_to_storage()
            .map_err(|e| format!("persist group: {e}"))?;
        Ok(group.group_id().to_vec())
    }

    /// The group conversation's extensions as of the current epoch;
    /// `None` for a group that is not a group conversation.
    ///
    /// # Errors
    /// The group is unknown, or its extensions are malformed.
    pub fn group_extensions(&self, group_id: &[u8]) -> Result<Option<GroupExtensions>, String> {
        let group = self.load_group(group_id)?;
        GroupExtensions::from_list(&group.context().extensions)
    }

    /// Stage a change to the group conversation's extensions for the
    /// next commit, by value (design D-5): `extensions` is the whole set
    /// as it should read afterwards. Who may change what is the rules'
    /// decision, made when the commit is built and again by every member
    /// that processes it.
    ///
    /// # Errors
    /// The group is unknown, is not a group conversation, or the
    /// extensions are malformed.
    pub fn propose_extensions(
        &mut self,
        group_id: &[u8],
        extensions: GroupExtensions,
    ) -> Result<(), String> {
        extensions.validate()?;
        if extensions.profile.v != GROUP_EXTENSION_VERSION {
            return Err("unsupported group extension version".to_owned());
        }
        if self.group_extensions(group_id)?.is_none() {
            return Err("this group is not a group conversation".to_owned());
        }
        let staged = self.staged.entry(group_id.to_vec()).or_default();
        // One context change per commit: the latest replaces the last.
        staged.retain(|p| !matches!(p, StagedProposal::Extensions(_)));
        staged.push(StagedProposal::Extensions(extensions));
        Ok(())
    }

    /// Propose removing this device's own leaf (design D-8): RFC 9420
    /// does not let a member commit its own removal, so this returns the
    /// bare proposal, by reference, for the next member online to commit
    /// whatever its role. The caller sends it to the group and then wipes
    /// the group locally.
    ///
    /// # Errors
    /// The group is unknown, or `mls-rs` refuses the proposal.
    pub fn propose_self_remove(&mut self, group_id: &[u8]) -> Result<Vec<u8>, String> {
        let mut group = self.load_group(group_id)?;
        let own = group.current_member_index();
        let message = group
            .propose_remove(own, Vec::new())
            .map_err(|e| format!("propose leave: {e}"))?;
        group
            .write_to_storage()
            .map_err(|e| format!("persist group: {e}"))?;
        message.to_bytes().map_err(|e| format!("serialize: {e}"))
    }

    /// Every leaf with its person and device, in leaf-index order — what
    /// the app groups into persons for the member list and for telling a
    /// new person from a new device (FR-19, FR-21).
    ///
    /// # Errors
    /// The group is unknown, or a leaf's credential is unreadable.
    pub fn group_roster(&self, group_id: &[u8]) -> Result<Vec<RosterEntry>, String> {
        let group = self.load_group(group_id)?;
        let own = group.current_member_index();
        group
            .roster()
            .members_iter()
            .map(|m| {
                let leaf = Leaf::of(m.signing_identity()).map_err(|e| e.to_string())?;
                Ok(RosterEntry {
                    index: m.index,
                    pin_subject: leaf.pin_subject().map_err(|e| e.to_string())?.to_owned(),
                    device_id: leaf.device_id.clone(),
                    airdress: leaf.airdress,
                    own: m.index == own,
                })
            })
            .collect()
    }

    /// This device's own pin subject, from its credential.
    fn own_pin_subject(&self) -> Result<String, String> {
        let identity = self.client.signing_identity().map_err(|e| e.to_string())?.0;
        Ok(Leaf::of(identity)
            .map_err(|e| e.to_string())?
            .pin_subject()
            .map_err(|e| e.to_string())?
            .to_owned())
    }
}
