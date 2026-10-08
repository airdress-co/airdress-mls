//! The rule matrix (SPEC-145 design D-5), through real engines.
//!
//! Every rule has an accepting case and a refusing one, and every refusal
//! is shown twice: the honest committer cannot build the commit, and a
//! commit built by a modified client (the rules switched off on its send
//! side, [`SEND_UNCHECKED`]) is refused by every honest receiver, which
//! stays at the epoch it was in.
//!
//! Persons here are airdress owners (`v: 2` leaves), as before persons
//! exist: Ana, Ben, Cleo and Dan, one airdress each.

use ed25519_dalek::SigningKey;

use super::{GroupRule, LEAF_CAP, PERSON_CAP, SEND_UNCHECKED};
use crate::credential::test_support::signed_delegation_json_v2;
use crate::engine::{MlsEngine, message_epoch};
use crate::group_context::{
    GroupExtensions, GroupPolicy, GroupProfile, GroupRoles, GroupSequencer, forced_roles,
};

const ANA: &str = "ana.test";
const BEN: &str = "ben.test";
const CLEO: &str = "cleo.test";
const DAN: &str = "dan.test";
const EXPIRES: &str = "2099-01-01T00:00:00Z";

struct Device {
    name: &'static str,
    airdress: &'static str,
    engine: MlsEngine,
    _dir: tempfile::TempDir,
}

impl Device {
    fn new(airdress: &'static str, name: &'static str, seed: u8) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = SigningKey::from_bytes(&[seed.wrapping_add(100); 32]);
        let seed = [seed; 32];
        let session = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let engine = MlsEngine::from_seed(
            airdress,
            &seed,
            &root.verifying_key().to_bytes(),
            &signed_delegation_json_v2(&root, airdress, &session, name, EXPIRES),
            dir.path().to_str().unwrap(),
            &[77u8; 32],
        )
        .unwrap();
        Self {
            name,
            airdress,
            engine,
            _dir: dir,
        }
    }
}

fn creation(creator: &str, policy: GroupPolicy) -> GroupExtensions {
    GroupExtensions {
        profile: GroupProfile {
            v: 1,
            title: "Ski trip".into(),
            avatar_sha256: None,
        },
        roles: GroupRoles {
            v: 1,
            admins: vec![creator.into()],
            join_order: vec![creator.into()],
        },
        policy,
        sequencer: GroupSequencer {
            v: 1,
            operator_fqdn: creator.into(),
            kid: "k-0011223344556677".into(),
        },
    }
}

struct Group {
    devices: Vec<Device>,
    id: Vec<u8>,
}

impl Group {
    /// `devices[0]` creates the group and adds every other device in one
    /// commit, as FR-6 does.
    fn found(mut devices: Vec<Device>, policy: GroupPolicy) -> Self {
        // A `v: 2` owner's pin subject is its airdress.
        let creator = devices[0].airdress;
        let id = devices[0]
            .engine
            .create_group_with_extensions(&creation(creator, policy))
            .unwrap();
        let kps: Vec<Vec<u8>> = devices[1..]
            .iter()
            .map(|d| d.engine.generate_key_package().unwrap())
            .collect();
        for kp in &kps {
            devices[0].engine.propose_add(&id, kp).unwrap();
        }
        let outcome = devices[0].engine.commit_pending(&id).unwrap();
        devices[0].engine.confirm_commit(&id).unwrap();
        let welcome = outcome.welcome.unwrap();
        for d in &mut devices[1..] {
            d.engine.process_welcome(&welcome).unwrap();
        }
        Self { devices, id }
    }

    fn get(&mut self, name: &str) -> &mut Device {
        self.devices.iter_mut().find(|d| d.name == name).unwrap()
    }

    fn epoch(&self, name: &str) -> u64 {
        let d = self.devices.iter().find(|d| d.name == name).unwrap();
        d.engine.group_epoch(&self.id).unwrap()
    }

    fn extensions(&self) -> GroupExtensions {
        self.devices[0]
            .engine
            .group_extensions(&self.id)
            .unwrap()
            .unwrap()
    }

    fn index_of(&self, name: &str) -> u32 {
        let d = self
            .devices
            .iter()
            .find(|d| d.engine.group_epoch(&self.id).is_some())
            .unwrap();
        d.engine
            .group_roster(&self.id)
            .unwrap()
            .into_iter()
            .find(|e| e.device_id.as_deref() == Some(name))
            .unwrap()
            .index
    }

    /// `by` commits what it staged; every other device that is in the
    /// group applies it.
    fn commit(&mut self, by: &str) -> Result<Vec<u8>, String> {
        let id = self.id.clone();
        let committer = self.get(by);
        let outcome = committer.engine.commit_pending(&id)?;
        committer.engine.confirm_commit(&id).unwrap();
        for peer in self.devices.iter_mut().filter(|d| d.name != by) {
            if peer.engine.group_epoch(&id).is_some() {
                peer.engine.process_commit(&id, &outcome.commit).unwrap();
            }
        }
        Ok(outcome.commit)
    }

    /// `by`, a modified client, commits what it staged with the rules off;
    /// every honest receiver refuses it with `rule` and stays put.
    fn refused_everywhere(&mut self, by: &str, rule: GroupRule) {
        let id = self.id.clone();
        SEND_UNCHECKED.with(|c| c.set(true));
        let built = self.get(by).engine.commit_pending(&id);
        SEND_UNCHECKED.with(|c| c.set(false));
        let commit = built.unwrap().commit;
        self.get(by).engine.confirm_commit(&id).unwrap();
        let sentence = rule.to_string();
        for peer in self.devices.iter_mut().filter(|d| d.name != by) {
            let Some(before) = peer.engine.group_epoch(&id) else {
                continue;
            };
            let err = peer
                .engine
                .process_commit(&id, &commit)
                .expect_err("an honest client refuses a rule-breaking commit")
                .to_string();
            assert!(err.contains(&sentence), "{}: {err}", peer.name);
            assert_eq!(peer.engine.group_epoch(&id), Some(before), "{}", peer.name);
        }
    }
}

fn three() -> Group {
    Group::found(
        vec![
            Device::new(ANA, "ana", 1),
            Device::new(BEN, "ben", 2),
            Device::new(CLEO, "cleo", 3),
        ],
        GroupPolicy::creation_default(),
    )
}

fn rule_error(result: Result<Vec<u8>, String>, rule: GroupRule) {
    let err = result.expect_err("the honest committer cannot build it");
    assert!(err.contains(&rule.to_string()), "{err}");
}

#[test]
fn the_creator_is_the_admin_and_the_roster_is_by_person() {
    let g = three();
    let ext = g.extensions();
    assert_eq!(ext.roles.admins, [ANA]);
    assert_eq!(ext.policy, GroupPolicy::creation_default());
    let roster = g.devices[1].engine.group_roster(&g.id).unwrap();
    let pins: Vec<&str> = roster.iter().map(|e| e.pin_subject.as_str()).collect();
    assert_eq!(pins, [ANA, BEN, CLEO]);
    assert_eq!(roster.iter().filter(|e| e.own).count(), 1);
    assert_eq!(roster[1].device_id.as_deref(), Some("ben"));
}

#[test]
fn a_creator_who_is_not_the_sole_admin_is_refused() {
    let mut d = Device::new(ANA, "ana", 1);
    let mut ext = creation(ANA, GroupPolicy::creation_default());
    ext.roles.admins = vec![BEN.into()];
    assert!(d.engine.create_group_with_extensions(&ext).is_err());
}

#[test]
fn only_an_admin_adds_a_person_unless_the_policy_says_so() {
    let mut g = three();
    let dan = Device::new(DAN, "dan", 4);
    let kp = dan.engine.generate_key_package().unwrap();
    let id = g.id.clone();
    g.get("ben").engine.propose_add(&id, &kp).unwrap();
    rule_error(g.commit("ben"), GroupRule::AddPerson);
    let kp = dan.engine.generate_key_package().unwrap();
    g.get("ben").engine.propose_add(&id, &kp).unwrap();
    g.refused_everywhere("ben", GroupRule::AddPerson);

    let mut open = Group::found(
        vec![
            Device::new(ANA, "ana", 1),
            Device::new(BEN, "ben", 2),
            Device::new(CLEO, "cleo", 3),
        ],
        GroupPolicy {
            members_may_add: true,
            ..GroupPolicy::creation_default()
        },
    );
    let id = open.id.clone();
    open.get("ben").engine.propose_add(&id, &kp).unwrap();
    assert!(open.commit("ben").is_ok(), "the policy lets members add");
}

#[test]
fn a_person_adds_their_own_device_and_nobody_elses() {
    let mut g = three();
    let id = g.id.clone();
    let ben2 = Device::new(BEN, "ben2", 5);
    let kp = ben2.engine.generate_key_package().unwrap();
    g.get("ben").engine.propose_add(&id, &kp).unwrap();
    assert!(g.commit("ben").is_ok(), "FR-11: a member's own new device");

    let ben3 = Device::new(BEN, "ben3", 6);
    let kp = ben3.engine.generate_key_package().unwrap();
    g.get("cleo").engine.propose_add(&id, &kp).unwrap();
    rule_error(g.commit("cleo"), GroupRule::AddDevice);
    let kp = ben3.engine.generate_key_package().unwrap();
    g.get("cleo").engine.propose_add(&id, &kp).unwrap();
    g.refused_everywhere("cleo", GroupRule::AddDevice);
}

#[test]
fn an_admin_removes_across_airdresses_and_a_member_cannot() {
    let mut g = three();
    let id = g.id.clone();
    let cleo = g.index_of("cleo");
    let err = g.get("ben").engine.propose_remove(&id, cleo).unwrap_err();
    assert!(err.contains(&GroupRule::RemoveOther.to_string()), "{err}");
    SEND_UNCHECKED.with(|c| c.set(true));
    g.get("ben").engine.propose_remove(&id, cleo).unwrap();
    SEND_UNCHECKED.with(|c| c.set(false));
    g.refused_everywhere("ben", GroupRule::RemoveOther);

    // F-1: the admin, from another airdress.
    let mut g = three();
    let id = g.id.clone();
    let cleo = g.index_of("cleo");
    g.get("ana").engine.propose_remove(&id, cleo).unwrap();
    let commit = g.get("ana").engine.commit_pending(&id).unwrap().commit;
    g.get("ana").engine.confirm_commit(&id).unwrap();
    g.get("ben").engine.process_commit(&id, &commit).unwrap();
    assert!(
        g.get("cleo")
            .engine
            .process_commit(&id, &commit)
            .unwrap()
            .self_removed
    );
}

#[test]
fn leaving_is_committed_by_whoever_is_next_whatever_their_role() {
    let mut g = three();
    let id = g.id.clone();
    let leave = g.get("cleo").engine.propose_self_remove(&id).unwrap();
    g.get("ana").engine.process_proposal(&id, &leave).unwrap();
    g.get("ben").engine.process_proposal(&id, &leave).unwrap();
    let commit = g.get("ben").engine.commit_pending(&id).unwrap().commit;
    g.get("ben").engine.confirm_commit(&id).unwrap();
    let out = g.get("ana").engine.process_commit(&id, &commit).unwrap();
    assert_eq!(out.removed.len(), 1);
    assert!(
        g.get("cleo")
            .engine
            .process_commit(&id, &commit)
            .unwrap()
            .self_removed
    );
}

#[test]
fn the_last_admin_leaving_forces_a_promotion() {
    let mut g = three();
    let id = g.id.clone();
    let leave = g.get("ana").engine.propose_self_remove(&id).unwrap();
    g.get("ben").engine.process_proposal(&id, &leave).unwrap();
    g.get("cleo").engine.process_proposal(&id, &leave).unwrap();

    // Without the promotion: refused on both sides.
    rule_error(g.commit("ben"), GroupRule::NoAdminLeft);
    g.refused_everywhere("ben", GroupRule::NoAdminLeft);
}

#[test]
fn with_the_forced_promotion_a_member_commits_the_last_admins_leave() {
    let mut g = three();
    let id = g.id.clone();
    let leave = g.get("ana").engine.propose_self_remove(&id).unwrap();
    g.get("ben").engine.process_proposal(&id, &leave).unwrap();
    g.get("cleo").engine.process_proposal(&id, &leave).unwrap();
    let mut ext = g.extensions();
    ext.roles = forced_roles(&ext.roles, &[BEN.to_owned(), CLEO.to_owned()]);
    assert_eq!(
        ext.roles.admins,
        [BEN],
        "the earliest-joined remaining person"
    );
    g.get("ben").engine.propose_extensions(&id, ext).unwrap();
    let commit = g.get("ben").engine.commit_pending(&id).unwrap().commit;
    g.get("ben").engine.confirm_commit(&id).unwrap();
    g.get("cleo").engine.process_commit(&id, &commit).unwrap();
    assert!(
        g.get("ana")
            .engine
            .process_commit(&id, &commit)
            .unwrap()
            .self_removed
    );
    let after = g.get("cleo").engine.group_extensions(&id).unwrap().unwrap();
    assert_eq!(after.roles.admins, [BEN]);

    // A member may not promote anyone else on the way out.
    let mut g = three();
    let id = g.id.clone();
    let leave = g.get("ana").engine.propose_self_remove(&id).unwrap();
    g.get("ben").engine.process_proposal(&id, &leave).unwrap();
    g.get("cleo").engine.process_proposal(&id, &leave).unwrap();
    let mut ext = g.extensions();
    ext.roles = forced_roles(&ext.roles, &[BEN.to_owned(), CLEO.to_owned()]);
    ext.roles.admins = vec![CLEO.into()];
    g.get("ben").engine.propose_extensions(&id, ext).unwrap();
    rule_error(g.commit("ben"), GroupRule::ChangeRoles);
}

#[test]
fn the_title_follows_the_policy_and_the_policy_is_the_admins() {
    let mut g = three();
    let id = g.id.clone();
    let mut ext = g.extensions();
    ext.profile.title = "Ski trip 2027".into();
    g.get("ben").engine.propose_extensions(&id, ext).unwrap();
    assert!(
        g.commit("ben").is_ok(),
        "everyone edits the title by default"
    );

    // A member may not change the policy.
    let mut ext = g.extensions();
    ext.policy.members_may_edit_profile = false;
    g.get("ben")
        .engine
        .propose_extensions(&id, ext.clone())
        .unwrap();
    rule_error(g.commit("ben"), GroupRule::ChangePolicy);
    g.get("ben").engine.propose_extensions(&id, ext).unwrap();
    g.refused_everywhere("ben", GroupRule::ChangePolicy);

    // The admin may; then the title is the admins'.
    let mut g = three();
    let id = g.id.clone();
    let mut ext = g.extensions();
    ext.policy.members_may_edit_profile = false;
    g.get("ana").engine.propose_extensions(&id, ext).unwrap();
    assert!(g.commit("ana").is_ok());
    let mut ext = g.extensions();
    ext.profile.title = "Mine now".into();
    g.get("ben")
        .engine
        .propose_extensions(&id, ext.clone())
        .unwrap();
    rule_error(g.commit("ben"), GroupRule::ChangeProfile);
    g.get("ben").engine.propose_extensions(&id, ext).unwrap();
    g.refused_everywhere("ben", GroupRule::ChangeProfile);
}

#[test]
fn roles_and_the_sequencer_are_the_admins() {
    let mut g = three();
    let id = g.id.clone();
    let mut promote_self = g.extensions();
    promote_self.roles.admins.push(BEN.into());
    // The join order is always the canonical one; only the admins differ.
    promote_self.roles.join_order = vec![ANA.into(), BEN.into(), CLEO.into()];
    g.get("ben")
        .engine
        .propose_extensions(&id, promote_self.clone())
        .unwrap();
    rule_error(g.commit("ben"), GroupRule::ChangeRoles);
    g.get("ben")
        .engine
        .propose_extensions(&id, promote_self.clone())
        .unwrap();
    g.refused_everywhere("ben", GroupRule::ChangeRoles);

    let mut g = three();
    let id = g.id.clone();
    let mut moved = g.extensions();
    moved.sequencer.operator_fqdn = BEN.into();
    g.get("ben")
        .engine
        .propose_extensions(&id, moved.clone())
        .unwrap();
    rule_error(g.commit("ben"), GroupRule::ChangeSequencer);
    g.get("ana").engine.propose_extensions(&id, moved).unwrap();
    assert!(g.commit("ana").is_ok());
    promote_self.sequencer = g.extensions().sequencer;
    g.get("ana")
        .engine
        .propose_extensions(&id, promote_self)
        .unwrap();
    assert!(g.commit("ana").is_ok(), "an admin makes Ben an admin");
    assert_eq!(g.extensions().roles.admins, [ANA, BEN]);
}

#[test]
fn a_member_moves_the_sequencer_in_the_commit_that_removes_its_last_person() {
    let mut g = three();
    let id = g.id.clone();
    let leave = g.get("cleo").engine.propose_self_remove(&id).unwrap();
    g.get("ana").engine.process_proposal(&id, &leave).unwrap();
    g.get("ben").engine.process_proposal(&id, &leave).unwrap();
    let mut moved = g.extensions();
    moved.sequencer.operator_fqdn = BEN.into();
    g.get("ben").engine.propose_extensions(&id, moved).unwrap();
    assert!(g.commit("ben").is_ok(), "D-12");
}

#[test]
fn the_committer_holds_the_person_cap() {
    PERSON_CAP.with(|c| c.set(3));
    let mut g = three();
    let id = g.id.clone();
    let dan = Device::new(DAN, "dan", 4);
    let kp = dan.engine.generate_key_package().unwrap();
    g.get("ana").engine.propose_add(&id, &kp).unwrap();
    let refused = g.commit("ana");
    PERSON_CAP.with(|c| c.set(crate::group_context::GROUP_MAX_PERSONS));
    rule_error(refused, GroupRule::TooManyPersons);
}

#[test]
fn a_message_says_its_epoch_before_it_is_processed() {
    let mut g = three();
    let id = g.id.clone();
    let before = g.epoch("ana");
    let titled = g_ext_titled(&g, "x");
    g.get("ben").engine.propose_extensions(&id, titled).unwrap();
    let commit = g.commit("ben").unwrap();
    assert_eq!(message_epoch(&commit).unwrap(), before);
    assert!(message_epoch(b"not mls").is_err());
}

fn g_ext_titled(g: &Group, title: &str) -> GroupExtensions {
    let mut ext = g.extensions();
    ext.profile.title = title.into();
    ext
}

#[test]
fn the_committer_holds_the_leaf_cap_too() {
    LEAF_CAP.with(|c| c.set(4));
    let mut g = three();
    let id = g.id.clone();
    let ben2 = Device::new(BEN, "ben2", 5);
    let kp = ben2.engine.generate_key_package().unwrap();
    g.get("ben").engine.propose_add(&id, &kp).unwrap();
    assert!(g.commit("ben").is_ok(), "four leaves");
    let ben3 = Device::new(BEN, "ben3", 6);
    let kp = ben3.engine.generate_key_package().unwrap();
    g.get("ben").engine.propose_add(&id, &kp).unwrap();
    let refused = g.commit("ben");
    LEAF_CAP.with(|c| c.set(crate::group_context::GROUP_LEAF_CAP));
    rule_error(refused, GroupRule::TooManyPersons);
}
