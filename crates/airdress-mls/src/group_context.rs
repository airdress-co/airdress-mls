//! What a group conversation keeps in its MLS group context.
//!
//! A group conversation across airdresses (SPEC-145 design D-5) carries
//! four group context extensions, so every member agrees on them and no
//! operator can read or assert them:
//!
//! | Extension | Type | Content |
//! |---|---|---|
//! | profile | [`PROFILE_EXTENSION`] | `{v, title, avatar_sha256?}` |
//! | roles | [`ROLES_EXTENSION`] | `{v, admins, join_order}` (pin subjects) |
//! | policy | [`POLICY_EXTENSION`] | `{v, members_may_add, members_may_edit_profile}` |
//! | sequencer | [`SEQUENCER_EXTENSION`] | `{v, operator_fqdn, kid}` |
//!
//! The type numbers are from RFC 9420's private-use range (`0xF000` to
//! `0xFFFF`, §17.3); each body is a small JSON object with a version field,
//! so a later version can be told from this one. A group is a *group
//! conversation* exactly when its context carries all four; a one-to-one or
//! self conversation carries none, and [`crate::rules`] treats it as it
//! always did.
//!
//! Changes travel as a `GroupContextExtensions` proposal in a commit, and
//! [`crate::group_rules`] decides who may make which.

use mls_rs::{Extension, ExtensionList};
use mls_rs_core::extension::ExtensionType;
use serde::{Deserialize, Serialize};

/// `airdress_group_profile`.
pub const PROFILE_EXTENSION: ExtensionType = ExtensionType::new(0xF5A1);
/// `airdress_group_roles`.
pub const ROLES_EXTENSION: ExtensionType = ExtensionType::new(0xF5A2);
/// `airdress_group_policy`.
pub const POLICY_EXTENSION: ExtensionType = ExtensionType::new(0xF5A3);
/// `airdress_group_sequencer`.
pub const SEQUENCER_EXTENSION: ExtensionType = ExtensionType::new(0xF5A4);

/// All four, in the order a client advertises them in its capabilities.
pub const GROUP_EXTENSION_TYPES: [ExtensionType; 4] = [
    PROFILE_EXTENSION,
    ROLES_EXTENSION,
    POLICY_EXTENSION,
    SEQUENCER_EXTENSION,
];

/// The version every body here is written at.
pub const GROUP_EXTENSION_VERSION: u8 = 1;

/// The most persons a group may hold (design D-11, the coordinator default
/// the owner may override). A committing device refuses an `Add` past it.
pub const GROUP_MAX_PERSONS: usize = 32;

/// The most leaves (devices) a group may hold (design D-11, NFR-5).
///
/// The number whose Welcome fits the operator's Welcome limit
/// (`chat.limits.max_welcome_bytes`, default 147 456 — a limit of its own
/// by the owner's ruling of 2026-10-09) with 20 % headroom. Measured by
/// `tests/welcome_size.rs`: 854 bytes a leaf plus 640 fixed, against a
/// 117 964-byte budget, is 137 leaves. 32 persons with 4 devices each (128
/// leaves, ~110 KB) fit. A committing device refuses past either cap.
pub const GROUP_LEAF_CAP: usize = 137;

/// The longest title, in characters (FR-17).
pub const GROUP_TITLE_MAX_CHARS: usize = 100;

/// `airdress_group_profile`: the title and the picture's hash. The picture
/// itself travels as a `group_avatar` block, shown only when its SHA-256
/// matches (design D-6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupProfile {
    /// Body version.
    pub v: u8,
    /// At most [`GROUP_TITLE_MAX_CHARS`] characters.
    pub title: String,
    /// SHA-256 of the current picture, lowercase hex; absent for none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_sha256: Option<String>,
}

/// `airdress_group_roles`: who is an admin, and the order persons joined
/// in — what FR-16's forced promotion reads. Both lists hold pin subjects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupRoles {
    /// Body version.
    pub v: u8,
    /// The admins' pin subjects.
    pub admins: Vec<String>,
    /// Every person's pin subject, earliest first, as of the last change
    /// to this extension. Persons added since are ordered after it by
    /// [`canonical_join_order`].
    pub join_order: Vec<String>,
}

/// `airdress_group_policy` (design D-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupPolicy {
    /// Body version.
    pub v: u8,
    /// Whether a member who is not an admin may add a person.
    pub members_may_add: bool,
    /// Whether a member who is not an admin may change the title and the
    /// picture.
    pub members_may_edit_profile: bool,
}

/// `airdress_group_sequencer`: the operator that orders the group's
/// commits (design D-3), by its FQDN and receipt key id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupSequencer {
    /// Body version.
    pub v: u8,
    /// The operator's FQDN.
    pub operator_fqdn: String,
    /// The id of the key its receipts verify against.
    pub kid: String,
}

/// The four extensions together: what a group conversation's context
/// holds, and the JSON form the FFI reads and writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupExtensions {
    /// Title and picture hash.
    pub profile: GroupProfile,
    /// Admins and join order.
    pub roles: GroupRoles,
    /// Who may add and who may edit the profile.
    pub policy: GroupPolicy,
    /// Who orders commits.
    pub sequencer: GroupSequencer,
}

impl GroupPolicy {
    /// The policy a creator's device writes (design D-6): admins add,
    /// everyone edits the title and picture.
    #[must_use]
    pub const fn creation_default() -> Self {
        Self {
            v: GROUP_EXTENSION_VERSION,
            members_may_add: false,
            members_may_edit_profile: true,
        }
    }
}

impl GroupExtensions {
    /// Refuse a body this version cannot vouch for.
    ///
    /// # Errors
    /// One sentence naming what is wrong.
    pub fn validate(&self) -> Result<(), String> {
        for (name, v) in [
            ("profile", self.profile.v),
            ("roles", self.roles.v),
            ("policy", self.policy.v),
            ("sequencer", self.sequencer.v),
        ] {
            if v != GROUP_EXTENSION_VERSION {
                return Err(format!("group {name} has unsupported version {v}"));
            }
        }
        if self.profile.title.chars().count() > GROUP_TITLE_MAX_CHARS {
            return Err("group title is longer than 100 characters".to_owned());
        }
        if let Some(hash) = &self.profile.avatar_sha256
            && (hash.len() != 64 || !hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        {
            return Err("group avatar_sha256 must be 64 lowercase hex characters".to_owned());
        }
        if self.roles.admins.is_empty() {
            return Err("a group needs at least one admin".to_owned());
        }
        if has_duplicates(&self.roles.admins) || has_duplicates(&self.roles.join_order) {
            return Err("group roles name a person twice".to_owned());
        }
        if self.sequencer.operator_fqdn.is_empty() || self.sequencer.kid.is_empty() {
            return Err("group sequencer needs an operator_fqdn and a kid".to_owned());
        }
        Ok(())
    }

    /// The extension list a group context carries.
    ///
    /// # Errors
    /// The bodies fail [`Self::validate`].
    pub fn to_list(&self) -> Result<ExtensionList, String> {
        self.validate()?;
        let mut list = ExtensionList::new();
        list.set(Extension::new(PROFILE_EXTENSION, encode(&self.profile)?));
        list.set(Extension::new(ROLES_EXTENSION, encode(&self.roles)?));
        list.set(Extension::new(POLICY_EXTENSION, encode(&self.policy)?));
        list.set(Extension::new(
            SEQUENCER_EXTENSION,
            encode(&self.sequencer)?,
        ));
        Ok(list)
    }

    /// Read the four extensions out of a context's list. `Ok(None)` when it
    /// carries none of them (not a group conversation).
    ///
    /// # Errors
    /// Some but not all are present, or one does not parse or validate.
    pub fn from_list(list: &ExtensionList) -> Result<Option<Self>, String> {
        let present: Vec<bool> = GROUP_EXTENSION_TYPES
            .iter()
            .map(|t| list.has_extension(*t))
            .collect();
        if present.iter().all(|p| !p) {
            return Ok(None);
        }
        if !present.iter().all(|p| *p) {
            return Err("a group context carries some of the group extensions but not all".into());
        }
        let read = |t: ExtensionType| {
            list.get(t)
                .map(|e| e.extension_data)
                .ok_or_else(|| "group extension vanished".to_owned())
        };
        let parsed = Self {
            profile: decode(&read(PROFILE_EXTENSION)?, "profile")?,
            roles: decode(&read(ROLES_EXTENSION)?, "roles")?,
            policy: decode(&read(POLICY_EXTENSION)?, "policy")?,
            sequencer: decode(&read(SEQUENCER_EXTENSION)?, "sequencer")?,
        };
        parsed.validate()?;
        Ok(Some(parsed))
    }
}

/// The join order a commit must leave behind (FR-16): the stored order,
/// kept to the persons still present, then the persons not yet in it, in
/// the order they appear in `present` (leaf order, then this commit's adds).
#[must_use]
pub fn canonical_join_order(stored: &[String], present: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for p in stored.iter().chain(present) {
        if present.contains(p) && !out.contains(p) {
            out.push(p.clone());
        }
    }
    out
}

/// The roles a commit must leave behind when it changes them on behalf of
/// a member who is not an admin: the admins still present, or — when none
/// is — the earliest-joined person (FR-16's forced promotion); and the
/// canonical join order.
#[must_use]
pub fn forced_roles(current: &GroupRoles, present: &[String]) -> GroupRoles {
    let join_order = canonical_join_order(&current.join_order, present);
    let mut admins: Vec<String> = current
        .admins
        .iter()
        .filter(|a| present.contains(a))
        .cloned()
        .collect();
    if admins.is_empty()
        && let Some(first) = join_order.first()
    {
        admins.push(first.clone());
    }
    GroupRoles {
        v: GROUP_EXTENSION_VERSION,
        admins,
        join_order,
    }
}

fn has_duplicates(list: &[String]) -> bool {
    list.iter().enumerate().any(|(i, a)| list[..i].contains(a))
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8], name: &str) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("group {name} does not parse: {e}"))
}

/// The fuzz entry: four bodies a peer chose, split on `0x00`, as the
/// four extensions of one context.
#[cfg(fuzzing)]
pub(crate) fn fuzz_from_list(bytes: &[u8]) {
    let mut parts = bytes.splitn(4, |b| *b == 0);
    let mut list = ExtensionList::new();
    for t in GROUP_EXTENSION_TYPES {
        list.set(Extension::new(t, parts.next().unwrap_or_default().to_vec()));
    }
    if let Ok(Some(parsed)) = GroupExtensions::from_list(&list) {
        assert!(parsed.validate().is_ok());
        let again = parsed.to_list().expect("a parsed set re-encodes");
        assert_eq!(GroupExtensions::from_list(&again), Ok(Some(parsed)));
    }
}

fn encode<T: Serialize>(body: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(body).map_err(|e| format!("group extension: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> GroupExtensions {
        GroupExtensions {
            profile: GroupProfile {
                v: 1,
                title: "Ski trip".into(),
                avatar_sha256: None,
            },
            roles: GroupRoles {
                v: 1,
                admins: vec!["ana.test".into()],
                join_order: vec!["ana.test".into()],
            },
            policy: GroupPolicy::creation_default(),
            sequencer: GroupSequencer {
                v: 1,
                operator_fqdn: "ana.test".into(),
                kid: "k-0011223344556677".into(),
            },
        }
    }

    #[test]
    fn the_types_are_private_use() {
        for t in GROUP_EXTENSION_TYPES {
            assert!((0xF000..=0xFFFF).contains(&t.raw_value()));
        }
    }

    #[test]
    fn a_list_round_trips_and_a_plain_list_is_no_group() {
        let ext = sample();
        let list = ext.to_list().unwrap();
        assert_eq!(GroupExtensions::from_list(&list).unwrap(), Some(ext));
        assert_eq!(
            GroupExtensions::from_list(&ExtensionList::new()).unwrap(),
            None
        );
    }

    #[test]
    fn half_a_group_is_refused() {
        let mut list = sample().to_list().unwrap();
        list.remove(POLICY_EXTENSION);
        assert!(GroupExtensions::from_list(&list).is_err());
    }

    #[test]
    fn bodies_carry_a_version_and_a_wrong_one_is_refused() {
        let list = sample().to_list().unwrap();
        let roles = list.get(ROLES_EXTENSION).unwrap().extension_data;
        let json: serde_json::Value = serde_json::from_slice(&roles).unwrap();
        assert_eq!(json["v"], 1);
        let mut ext = sample();
        ext.policy.v = 2;
        assert!(ext.validate().unwrap_err().contains("version"));
    }

    #[test]
    fn what_validate_refuses() {
        let mut no_admin = sample();
        no_admin.roles.admins.clear();
        assert!(no_admin.validate().is_err());
        let mut long = sample();
        long.profile.title = "x".repeat(101);
        assert!(long.validate().is_err());
        let mut bad_hash = sample();
        bad_hash.profile.avatar_sha256 = Some("ABC".into());
        assert!(bad_hash.validate().is_err());
        let mut twice = sample();
        twice.roles.admins = vec!["a".into(), "a".into()];
        assert!(twice.validate().is_err());
    }

    #[test]
    fn the_canonical_order_keeps_who_stayed_then_appends_who_came() {
        let stored = ["a", "b", "c"].map(String::from);
        let present = ["c", "a", "d"].map(String::from);
        assert_eq!(canonical_join_order(&stored, &present), ["a", "c", "d"]);
    }

    #[test]
    fn forced_promotion_picks_the_earliest_joined_only_when_no_admin_is_left() {
        let roles = GroupRoles {
            v: 1,
            admins: vec!["a".into()],
            join_order: ["a", "b", "c"].map(String::from).to_vec(),
        };
        let without_a = ["c", "b"].map(String::from);
        assert_eq!(forced_roles(&roles, &without_a).admins, ["b"]);
        let with_a = ["a", "c"].map(String::from);
        assert_eq!(forced_roles(&roles, &with_a).admins, ["a"]);
    }
}
