//! What a receiver refuses whatever the sender's client was built to do,
//! through real engines in strict mode, past the cutover, with the
//! sender's send-side checks switched off where it matters, as a modified
//! client would ([`SEND_UNCHECKED`]):
//!
//! - a conversation keeps the kind it was founded with: a one-to-one, self
//!   or household group never takes on the group extensions;
//! - a message is accepted as from an airdress only if the leaf MLS
//!   authenticated belongs to it.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use mls_rs::ExtensionList;

use super::{MlsEngine, StagedProposal};
use crate::credential::{DeviceStatus, test_support::signed_delegation_json_v2};
use crate::group_context::{
    GroupExtensions, GroupPolicy, GroupProfile, GroupRoles, GroupSequencer,
};
use crate::group_rules::tests::{Group, rule_error, three};
use crate::group_rules::{GroupRule, SEND_UNCHECKED};

const ALICE: &str = "alice.test";
const BOB: &str = "bob.test";

fn root_of(airdress: &str) -> SigningKey {
    SigningKey::from_bytes(&[if airdress == ALICE { 101 } else { 102 }; 32])
}

fn device(airdress: &str, name: &str, seed: u8, dir: &tempfile::TempDir) -> MlsEngine {
    let root = root_of(airdress);
    let session = SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes();
    let engine = MlsEngine::from_seed(
        airdress,
        &[seed; 32],
        &root.verifying_key().to_bytes(),
        &signed_delegation_json_v2(&root, airdress, &session, name, "2099-01-01T00:00:00Z"),
        dir.path().to_str().unwrap(),
        &[7u8; 32],
    )
    .unwrap();
    engine.set_root_key_lookup(Arc::new(|a: &str| {
        [ALICE, BOB]
            .contains(&a)
            .then(|| root_of(a).verifying_key().to_bytes())
    }));
    engine.set_revocation_lookup(Arc::new(|_: &str| Some(DeviceStatus::Active)));
    engine.set_v2_cutover();
    engine
}

/// Alice's phone and tablet and Bob's phone in one one-to-one group.
struct OneToOne {
    phone: MlsEngine,
    tablet: MlsEngine,
    bob: MlsEngine,
    group: Vec<u8>,
    _dirs: [tempfile::TempDir; 3],
}

fn one_to_one() -> OneToOne {
    let dirs = [
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    ];
    let mut phone = device(ALICE, "alice-phone", 1, &dirs[0]);
    let mut tablet = device(ALICE, "alice-tablet", 2, &dirs[1]);
    let mut bob = device(BOB, "bob-phone", 3, &dirs[2]);
    let out = phone
        .start_group(&bob.generate_key_package().unwrap(), b"hi", ALICE)
        .unwrap();
    let group = out.group_id.clone();
    bob.process_welcome(&out.welcome).unwrap();
    phone
        .propose_add(&group, &tablet.generate_key_package().unwrap())
        .unwrap();
    let c = phone.commit_pending(&group).unwrap();
    phone.confirm_commit(&group).unwrap();
    bob.process_commit(&group, &c.commit).unwrap();
    tablet.process_welcome(&c.welcome.unwrap()).unwrap();
    OneToOne {
        phone,
        tablet,
        bob,
        group,
        _dirs: dirs,
    }
}

fn naming_bob_admin() -> GroupExtensions {
    GroupExtensions {
        profile: GroupProfile {
            v: 1,
            title: "x".into(),
            avatar_sha256: None,
        },
        roles: GroupRoles {
            v: 1,
            admins: vec![BOB.into()],
            join_order: vec![BOB.into()],
        },
        policy: GroupPolicy::creation_default(),
        sequencer: GroupSequencer {
            v: 1,
            operator_fqdn: BOB.into(),
            kid: "k".into(),
        },
    }
}

/// Bob builds a commit carrying `proposal` with his rules switched off.
fn unchecked_commit(t: &mut OneToOne, proposal: StagedProposal) -> Vec<u8> {
    SEND_UNCHECKED.with(|c| c.set(true));
    t.bob
        .staged
        .entry(t.group.clone())
        .or_default()
        .push(proposal);
    let built = t.bob.commit_pending(&t.group);
    SEND_UNCHECKED.with(|c| c.set(false));
    built.unwrap().commit
}

#[test]
fn a_one_to_one_never_becomes_a_group() {
    let mut t = one_to_one();
    let before = t.phone.group_epoch(&t.group);
    let commit = unchecked_commit(&mut t, StagedProposal::Extensions(naming_bob_admin()));
    for (who, engine) in [("phone", &mut t.phone), ("tablet", &mut t.tablet)] {
        let refused = engine.process_commit(&t.group, &commit);
        assert!(
            refused.is_err(),
            "alice-{who} accepted group extensions in a one-to-one"
        );
    }
    assert_eq!(
        t.phone.group_epoch(&t.group),
        before,
        "the refusal left the epoch"
    );

    // And with no promotion, Bob still cannot remove Alice's tablet.
    let tablet = t
        .phone
        .group_members(&t.group)
        .unwrap()
        .into_iter()
        .find(|m| m.identity.ends_with(b"alice-tablet"))
        .unwrap()
        .index;
    assert!(t.bob.propose_remove(&t.group, tablet).is_err());
}

#[test]
fn an_honest_sender_cannot_build_group_extensions_into_a_one_to_one() {
    let mut t = one_to_one();
    t.bob
        .staged
        .entry(t.group.clone())
        .or_default()
        .push(StagedProposal::Extensions(naming_bob_admin()));
    assert!(t.bob.commit_pending(&t.group).is_err());
}

#[test]
fn a_partial_set_of_group_extensions_is_refused_and_the_group_stays_usable() {
    let mut t = one_to_one();
    // One of the four group extensions, which on its own would make every
    // later commit unreadable (some but not all present).
    let full = naming_bob_admin().to_list().unwrap();
    let mut partial = ExtensionList::new();
    let first = crate::group_context::GROUP_EXTENSION_TYPES[0];
    partial.set(full.get(first).unwrap());
    let commit = unchecked_commit(&mut t, StagedProposal::RawExtensions(partial));
    assert!(t.phone.process_commit(&t.group, &commit).is_err());

    // The group still takes an ordinary commit afterwards.
    let late_dir = tempfile::tempdir().unwrap();
    let mut late = device(ALICE, "alice-laptop", 4, &late_dir);
    t.phone
        .propose_add(&t.group, &late.generate_key_package().unwrap())
        .unwrap();
    let c = t.phone.commit_pending(&t.group).unwrap();
    t.phone.confirm_commit(&t.group).unwrap();
    t.tablet.process_commit(&t.group, &c.commit).unwrap();
    late.process_welcome(&c.welcome.unwrap()).unwrap();
}

#[test]
fn a_member_cannot_send_under_another_members_airdress() {
    let mut t = one_to_one();
    // Bob names Alice in his binding, and the envelope says Alice too.
    let forged = t.bob.encrypt(&t.group, b"I am alice", ALICE).unwrap();
    assert!(
        t.tablet.decrypt(&t.group, &forged, ALICE).is_err(),
        "a message from Bob's leaf was accepted as Alice's"
    );
    // Bob's honest message still reads, as his.
    let honest = t.bob.encrypt(&t.group, b"hi from bob", BOB).unwrap();
    let got = t
        .tablet
        .decrypt_with_sender(&t.group, &honest, BOB)
        .unwrap();
    assert_eq!(got.plaintext, b"hi from bob");
    assert_eq!(got.sender.airdress, BOB);
}

// ---------------------------------------------------------------------
// Group conversations: what the group rules do not name
// ---------------------------------------------------------------------

/// `by` builds a commit holding only a `ReInit`, with or without its rules.
fn reinit_commit(engine: &MlsEngine, group: &[u8], unchecked: bool) -> Result<Vec<u8>, String> {
    let mut g = engine.load_group(group)?;
    let suite = g.cipher_suite();
    SEND_UNCHECKED.with(|c| c.set(unchecked));
    let built = g
        .commit_builder()
        .reinit(
            None,
            mls_rs::ProtocolVersion::MLS_10,
            suite,
            ExtensionList::new(),
        )
        .map_err(|e| e.to_string())
        .and_then(|b| b.build().map_err(|e| e.to_string()));
    SEND_UNCHECKED.with(|c| c.set(false));
    built?.commit_message.to_bytes().map_err(|e| e.to_string())
}

#[test]
fn a_group_member_cannot_reinitialise_the_group() {
    let mut g = three();
    let id = g.id.clone();
    let honest = reinit_commit(&g.get("ben").engine, &id, false);
    let err = honest.expect_err("the honest committer cannot build a ReInit");
    assert!(
        err.contains(&GroupRule::UnsupportedProposal.to_string()),
        "{err}"
    );

    let commit = reinit_commit(&g.get("ben").engine, &id, true).unwrap();
    for who in ["ana", "cleo"] {
        let before = g.get(who).engine.group_epoch(&id);
        let err = g
            .get(who)
            .engine
            .process_commit(&id, &commit)
            .expect_err("a ReInit is refused")
            .to_string();
        assert!(
            err.contains(&GroupRule::UnsupportedProposal.to_string()),
            "{who}: {err}"
        );
        assert_eq!(g.get(who).engine.group_epoch(&id), before);
    }
}

#[test]
fn a_one_to_one_cannot_be_reinitialised() {
    let mut t = one_to_one();
    let honest = reinit_commit(&t.bob, &t.group, false);
    assert!(
        honest.is_err(),
        "the honest committer cannot build a ReInit"
    );
    let commit = reinit_commit(&t.bob, &t.group, true).unwrap();
    let before = t.phone.group_epoch(&t.group);
    let err = t
        .phone
        .process_commit(&t.group, &commit)
        .expect_err("a ReInit is refused")
        .to_string();
    assert!(
        err.contains(&GroupRule::UnsupportedProposal.to_string()),
        "{err}"
    );
    assert_eq!(t.phone.group_epoch(&t.group), before);
}

/// The group's own four extensions, unchanged, plus one more.
fn with_an_extra_extension(g: &Group) -> ExtensionList {
    let mut list = g.extensions().to_list().unwrap();
    list.set_from(mls_rs::extension::built_in::RequiredCapabilitiesExt::default())
        .unwrap();
    list
}

#[test]
fn only_an_admin_changes_the_groups_other_extensions() {
    let mut g = three();
    let id = g.id.clone();
    let extra = with_an_extra_extension(&g);
    let stage = |g: &mut Group, who: &str, list: &ExtensionList| {
        g.get(who)
            .engine
            .staged
            .entry(id.clone())
            .or_default()
            .push(StagedProposal::RawExtensions(list.clone()));
    };
    stage(&mut g, "ben", &extra);
    rule_error(g.commit("ben"), GroupRule::ChangeOtherExtensions);
    stage(&mut g, "ben", &extra);
    g.refused_everywhere("ben", GroupRule::ChangeOtherExtensions);

    let mut g = three();
    let extra = with_an_extra_extension(&g);
    stage(&mut g, "ana", &extra);
    assert!(g.commit("ana").is_ok(), "an admin may");
}

#[test]
fn an_unreadable_proposed_change_does_not_hold_up_the_next_commit() {
    let mut g = three();
    let id = g.id.clone();
    // Ben proposes, by reference, one group extension of the four.
    let full = g.extensions().to_list().unwrap();
    let mut partial = ExtensionList::new();
    partial.set(
        full.get(crate::group_context::GROUP_EXTENSION_TYPES[0])
            .unwrap(),
    );
    let proposal = {
        let mut group = g.get("ben").engine.load_group(&id).unwrap();
        group
            .propose_group_context_extensions(partial, Vec::new())
            .unwrap()
            .to_bytes()
            .unwrap()
    };
    g.get("ana")
        .engine
        .process_proposal(&id, &proposal)
        .unwrap();

    // Ana's next commit builds, without it, and Cleo applies it.
    let before = g.get("cleo").engine.group_epoch(&id).unwrap();
    g.commit("ana").expect("an unrelated commit still builds");
    assert_eq!(g.get("cleo").engine.group_epoch(&id), Some(before + 1));
}
