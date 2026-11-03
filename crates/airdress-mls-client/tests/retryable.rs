//! What the client leaves for a replay because a later attempt can
//! succeed: an envelope whose effect the engine could not write, and a
//! commit refused only because this device does not yet hold a device
//! revoked.
#![allow(
    clippy::tests_outside_test_module,
    missing_docs,
    reason = "an integration test file has no cfg(test) module by construction"
)]

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use airdress_mls::MlsEngine;
use airdress_mls::credential::test_support::{
    signed_delegation_json_v2, signed_delegation_json_v3,
};
use airdress_mls::credential::{DeviceStatus, pin_subject_for_person};
use airdress_mls_client::client::MAX_DEFERRALS;
use airdress_mls_client::{Client, Event, InboundEnvelope, LanePayload, OutboundEnvelope};
use ed25519_dalek::SigningKey;

const HOME: &str = "home.example";
const PERSON_A: &str = "0b6f2c1e-0000-4000-8000-00000000000a";
const PERSON_B: &str = "0b6f2c1e-0000-4000-8000-00000000000b";

/// One root per pin subject: the owner's under the bare airdress, each
/// person's under their own subject, so the root-key lookup answers any
/// subject by itself.
fn root_for(subject: &str) -> SigningKey {
    let mut seed = [0x5au8; 32];
    for (i, byte) in subject.bytes().enumerate() {
        seed[i % 32] ^= byte.wrapping_add(u8::try_from(i % 251).unwrap_or(0));
    }
    SigningKey::from_bytes(&seed)
}

/// The revocation state a device's host holds, keyed by pin subject and
/// `device_id`.
type Revoked = Arc<Mutex<HashSet<(String, String)>>>;

struct Device {
    airdress: String,
    subject: String,
    leaf_id: String,
    seed: [u8; 32],
    root: [u8; 32],
    delegation: String,
    dir: tempfile::TempDir,
    key: [u8; 32],
    revoked: Revoked,
}

impl Device {
    /// A device of the owner of `airdress` (`person` `None`), or of a
    /// person of [`HOME`].
    fn new(airdress: &str, person: Option<&str>, n: u8) -> Self {
        let seed = [n; 32];
        let device_id = format!("device-{n}");
        let session = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let expires = "2099-01-01T00:00:00Z";
        let (subject, delegation) = match person {
            None => {
                let root = root_for(airdress);
                (
                    airdress.to_owned(),
                    signed_delegation_json_v2(&root, airdress, &session, &device_id, expires),
                )
            }
            Some(person) => {
                let subject = pin_subject_for_person(airdress, person);
                let root = root_for(&subject);
                let json = signed_delegation_json_v3(
                    &root, airdress, person, &session, &device_id, expires,
                );
                (subject, json)
            }
        };
        Self {
            airdress: airdress.to_owned(),
            root: root_for(&subject).verifying_key().to_bytes(),
            subject,
            leaf_id: device_id,
            seed,
            delegation,
            dir: tempfile::tempdir().unwrap(),
            key: [n.wrapping_add(50); 32],
            revoked: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    fn open(&self) -> Client {
        let engine = MlsEngine::from_seed(
            &self.airdress,
            &self.seed,
            &self.root,
            &self.delegation,
            self.dir.path().join("mls").to_str().unwrap(),
            &self.key,
        )
        .unwrap();
        engine.set_v2_cutover();
        let view = Arc::clone(&self.revoked);
        engine.set_revocation_lookup(Arc::new(move |s: &str, d: &str| {
            Some(
                if view.lock().unwrap().contains(&(s.to_owned(), d.to_owned())) {
                    DeviceStatus::Revoked
                } else {
                    DeviceStatus::Active
                },
            )
        }));
        engine.set_root_key_lookup(Arc::new(|subject: &str| {
            Some(root_for(subject).verifying_key().to_bytes())
        }));
        Client::open(engine, &self.dir.path().join("client"), &self.key).unwrap()
    }

    /// This device's host learns that `other` is revoked.
    fn learns_revoked(&self, other: &Self) {
        self.revoked
            .lock()
            .unwrap()
            .insert((other.subject.clone(), other.leaf_id.clone()));
    }

    /// The member identity `other` has in a group.
    fn member_identity(other: &Self) -> Vec<u8> {
        [other.subject.as_bytes(), &[0x1F], other.leaf_id.as_bytes()].concat()
    }
}

fn deliver(out: &OutboundEnvelope, from: &str, conversation: &str) -> InboundEnvelope {
    InboundEnvelope {
        envelope_id: out.idempotency_key.clone(),
        conversation_id: conversation.to_owned(),
        envelope_kind: out.envelope_kind.clone(),
        from_airdress: from.to_owned(),
        ciphertext: out.ciphertext.clone(),
        commit_from_epoch: out.commit_from_epoch,
        duration_ms: None,
        received_at: Some("2026-10-06T00:00:00Z".to_owned()),
    }
}

fn text(t: &str) -> Vec<u8> {
    LanePayload::encode_device(&serde_json::json!([{"type": "text", "text": t}])).unwrap()
}

/// Make every write of the engine's group state fail until dropped,
/// while it stays readable: the `groups` directory is read-only, so no
/// sealed file can be created in it.
struct UnwritableGroups {
    path: PathBuf,
}

impl UnwritableGroups {
    fn of(device: &Device) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let path = device.dir.path().join("mls").join("groups");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o555)).unwrap();
        Self { path }
    }
}

impl Drop for UnwritableGroups {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn assert_left_for_replay(p: &airdress_mls_client::Processed) {
    assert!(!p.ack, "{:?}", p.event);
    assert!(
        matches!(
            p.event,
            Event::Failed {
                retryable: true,
                ..
            }
        ),
        "{:?}",
        p.event
    );
}

fn message_text(event: &Event) -> String {
    match event {
        Event::Message(m) => m.blocks[0]["text"].as_str().unwrap().to_owned(),
        other => panic!("expected a message, got {other:?}"),
    }
}

/// Alice's and Bob's clients in one conversation, and its group id.
fn pair(a: &Device, b: &Device) -> (Client, Client, Vec<u8>) {
    let mut alice = a.open();
    let mut bob = b.open();
    let kp = bob.key_packages(1).unwrap().remove(0);
    let out = alice
        .establish("conv-a", &b.airdress, &kp, &text("hello"), &a.airdress)
        .unwrap();
    for env in &out {
        assert!(bob.process(&deliver(env, &a.airdress, "conv-b")).ack);
    }
    let group_id = alice.directory().group_for("conv-a").unwrap();
    (alice, bob, group_id)
}

#[test]
fn a_welcome_whose_join_could_not_be_stored_joins_on_replay() {
    let a = Device::new("alice.example", None, 61);
    let b = Device::new("bob.example", None, 62);
    let mut alice = a.open();
    let mut bob = b.open();
    let kp = bob.key_packages(1).unwrap().remove(0);
    let out = alice
        .establish(
            "conv-a",
            "bob.example",
            &kp,
            &text("hello"),
            "alice.example",
        )
        .unwrap();
    {
        let _blocked = UnwritableGroups::of(&b);
        assert_left_for_replay(&bob.process(&deliver(&out[0], "alice.example", "conv-b")));
        assert!(bob.directory().group_for("conv-b").is_none());
    }
    let joined = bob.process(&deliver(&out[0], "alice.example", "conv-b"));
    assert!(joined.ack);
    assert!(
        matches!(joined.event, Event::Joined { .. }),
        "{:?}",
        joined.event
    );
    let first = bob.process(&deliver(&out[1], "alice.example", "conv-b"));
    assert_eq!(message_text(&first.event), "hello");
}

#[test]
fn a_message_whose_decryption_could_not_be_stored_decrypts_on_replay() {
    let a = Device::new("alice.example", None, 63);
    let b = Device::new("bob.example", None, 64);
    let (mut alice, mut bob, _) = pair(&a, &b);
    let msg = alice
        .encrypt("conv-a", &text("kept"), "alice.example")
        .unwrap();
    {
        let _blocked = UnwritableGroups::of(&b);
        assert_left_for_replay(&bob.process(&deliver(&msg, "alice.example", "conv-b")));
    }
    let got = bob.process(&deliver(&msg, "alice.example", "conv-b"));
    assert!(got.ack);
    assert_eq!(message_text(&got.event), "kept");
}

#[test]
fn a_commit_whose_effect_could_not_be_stored_applies_on_replay() {
    let a = Device::new("alice.example", None, 65);
    let b = Device::new("bob.example", None, 66);
    let c = Device::new("alice.example", None, 67);
    let (mut alice, mut bob, group_id) = pair(&a, &b);
    let carol_kp = c.open().key_packages(1).unwrap().remove(0);
    let prepared = alice.prepare_add("conv-a", &[carol_kp]).unwrap();
    alice.confirm_commit("conv-a").unwrap();
    let epoch = bob.engine().group_epoch(&group_id);
    {
        let _blocked = UnwritableGroups::of(&b);
        assert_left_for_replay(&bob.process(&deliver(&prepared.commit, "alice.example", "conv-b")));
    }
    assert_eq!(bob.engine().group_epoch(&group_id), epoch);
    let applied = bob.process(&deliver(&prepared.commit, "alice.example", "conv-b"));
    assert!(applied.ack);
    assert!(
        matches!(applied.event, Event::Membership { ref added, .. } if added.len() == 1),
        "{:?}",
        applied.event
    );
}

/// A commit left for a replay holds its group: the message and the commit
/// of the epoch after it are left too, rather than failing against the
/// epoch before, and all three apply in order once the replay comes.
#[test]
fn envelopes_behind_a_commit_left_for_a_replay_wait_for_it() {
    let a = Device::new("alice.example", None, 68);
    let b = Device::new("bob.example", None, 69);
    let c = Device::new("alice.example", None, 70);
    let (mut alice, mut bob, group_id) = pair(&a, &b);
    let carol_kp = c.open().key_packages(1).unwrap().remove(0);
    let add = alice.prepare_add("conv-a", &[carol_kp]).unwrap();
    alice.confirm_commit("conv-a").unwrap();
    let message = alice
        .encrypt("conv-a", &text("after the add"), "alice.example")
        .unwrap();
    let rotation = alice.prepare_add("conv-a", &[]).unwrap();
    alice.confirm_commit("conv-a").unwrap();
    let envs: Vec<InboundEnvelope> = [&add.commit, &message, &rotation.commit]
        .into_iter()
        .map(|e| deliver(e, "alice.example", "conv-b"))
        .collect();

    let epoch = bob.engine().group_epoch(&group_id);
    {
        let _blocked = UnwritableGroups::of(&b);
        assert_left_for_replay(&bob.process(&envs[0]));
    }
    // Storage is back, but the commit has not been replayed yet.
    assert_left_for_replay(&bob.process(&envs[1]));
    assert_left_for_replay(&bob.process(&envs[2]));
    assert_eq!(bob.engine().group_epoch(&group_id), epoch);

    // The replay, in order.
    let applied = bob.process(&envs[0]);
    assert!(
        matches!(applied.event, Event::Membership { ref added, .. } if added.len() == 1),
        "{:?}",
        applied.event
    );
    let got = bob.process(&envs[1]);
    assert!(got.ack);
    assert_eq!(message_text(&got.event), "after the add");
    let rotated = bob.process(&envs[2]);
    assert!(rotated.ack, "{:?}", rotated.event);
    assert!(
        matches!(rotated.event, Event::Membership { .. }),
        "{:?}",
        rotated.event
    );
    assert_eq!(bob.engine().group_epoch(&group_id), epoch.map(|e| e + 2));
}

/// The owner's device, a device of person A and one of person B, in one
/// conversation: `(devices, clients)`, the owner's first.
fn household(base: u8) -> (Vec<Device>, Vec<Client>) {
    let devices = vec![
        Device::new(HOME, None, base),
        Device::new(HOME, Some(PERSON_A), base + 1),
        Device::new(HOME, Some(PERSON_B), base + 2),
    ];
    let mut clients: Vec<Client> = devices.iter().map(Device::open).collect();
    let kp = clients[1].key_packages(1).unwrap().remove(0);
    let out = clients[0]
        .establish("conv", HOME, &kp, &text("hi"), HOME)
        .unwrap();
    for env in &out {
        assert!(clients[1].process(&deliver(env, HOME, "conv")).ack);
    }
    let kp = clients[2].key_packages(1).unwrap().remove(0);
    let add = clients[0].prepare_add("conv", &[kp]).unwrap();
    clients[0].confirm_commit("conv").unwrap();
    assert!(clients[1].process(&deliver(&add.commit, HOME, "conv")).ack);
    let welcome = add.welcome.unwrap();
    assert!(clients[2].process(&deliver(&welcome, HOME, "conv")).ack);
    (devices, clients)
}

/// The owner's device removes person B's device, which its own host holds
/// revoked; person A's device has not heard yet.
fn remove_person_b(devices: &[Device], clients: &mut [Client]) -> InboundEnvelope {
    devices[0].learns_revoked(&devices[2]);
    let removal = clients[0]
        .prepare_remove("conv", &[Device::member_identity(&devices[2])])
        .unwrap();
    clients[0].confirm_commit("conv").unwrap();
    deliver(&removal.commit, HOME, "conv")
}

#[test]
fn a_removal_of_a_device_not_yet_known_revoked_is_left_for_a_replay() {
    let (devices, mut clients) = household(70);
    let env = remove_person_b(&devices, &mut clients);

    let refused = clients[1].process(&env);
    assert_left_for_replay(&refused);
    assert!(clients[1].directory().group_for("conv").is_some());

    // The host refreshes its revocation state; the replay applies.
    devices[1].learns_revoked(&devices[2]);
    let applied = clients[1].process(&env);
    assert!(applied.ack, "{:?}", applied.event);
    assert!(
        matches!(applied.event, Event::Membership { ref removed, .. } if removed.len() == 1),
        "{:?}",
        applied.event
    );
}

#[test]
fn a_removal_a_refreshed_view_still_refuses_asks_to_rejoin_after_a_bound() {
    let (devices, mut clients) = household(80);
    let env = remove_person_b(&devices, &mut clients);
    drop(clients.remove(1));
    let mut last = None;
    for attempt in 1..=MAX_DEFERRALS {
        let mut person_a = devices[1].open();
        let p = person_a.process(&env);
        if attempt < MAX_DEFERRALS {
            assert_left_for_replay(&p);
        }
        last = Some(p);
    }
    let last = last.unwrap();
    assert!(last.ack, "{:?}", last.event);
    assert!(
        matches!(last.event, Event::RejoinNeeded { .. }),
        "{:?}",
        last.event
    );
}
