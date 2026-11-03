//! What the client refuses from an envelope whatever the operator filed
//! it under, and what "accept" pins for a changed root key.
#![allow(
    clippy::tests_outside_test_module,
    missing_docs,
    reason = "an integration test file has no cfg(test) module by construction"
)]

use airdress_mls::MlsEngine;
use airdress_mls::credential::test_support::signed_delegation_json_v2;
use airdress_mls_client::{
    Client, Event, InboundEnvelope, LanePayload, OutboundEnvelope, PinStore,
};
use ed25519_dalek::SigningKey;

/// One root per airdress, as a real deployment has: every device of
/// an airdress is delegated by the same root, so the root-key lookup
/// below can answer by airdress alone.
fn root_for(airdress: &str) -> SigningKey {
    let mut seed = [0x5au8; 32];
    for (i, byte) in airdress.bytes().enumerate() {
        seed[i % 32] ^= byte.wrapping_add(u8::try_from(i % 251).unwrap_or(0));
    }
    SigningKey::from_bytes(&seed)
}

struct Device {
    airdress: String,
    seed: [u8; 32],
    root: [u8; 32],
    delegation: String,
    dir: tempfile::TempDir,
    key: [u8; 32],
}

impl Device {
    fn new(airdress: &str, n: u8) -> Self {
        let seed = [n; 32];
        let root = root_for(airdress);
        let session = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let delegation = signed_delegation_json_v2(
            &root,
            airdress,
            &session,
            &format!("device-{n}"),
            "2099-01-01T00:00:00Z",
        );
        Self {
            airdress: airdress.to_owned(),
            seed,
            root: root.verifying_key().to_bytes(),
            delegation,
            dir: tempfile::tempdir().unwrap(),
            key: [n.wrapping_add(50); 32],
        }
    }

    fn open_with(&self, cutover: bool) -> Client {
        let engine = MlsEngine::from_seed(
            &self.airdress,
            &self.seed,
            &self.root,
            &self.delegation,
            self.dir.path().join("mls").to_str().unwrap(),
            &self.key,
        )
        .unwrap();
        if cutover {
            engine.set_v2_cutover();
        }
        engine.set_revocation_lookup(std::sync::Arc::new(|_: &str, _: &str| {
            Some(airdress_mls::credential::DeviceStatus::Active)
        }));
        // Past the cutover check 2 needs a root-key lookup too.
        engine.set_root_key_lookup(std::sync::Arc::new(|subject: &str| {
            Some(root_for(subject).verifying_key().to_bytes())
        }));
        Client::open(engine, &self.dir.path().join("client"), &self.key).unwrap()
    }

    fn open(&self) -> Client {
        self.open_with(true)
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

/// Alice (the victim) and Bob in one conversation: alice "conv-b", bob "conv-b@bob".
fn pair(a: &Device, b: &Device) -> (Client, Client) {
    let mut alice = a.open();
    let mut bob = b.open();
    let kp = bob.key_packages(1).unwrap().remove(0);
    let out = alice
        .establish(
            "conv-b",
            "bob.example",
            &kp,
            &text("hello"),
            "alice.example",
        )
        .unwrap();
    assert!(matches!(
        bob.process(&deliver(&out[0], "alice.example", "conv-b@bob"))
            .event,
        Event::Joined { .. }
    ));
    assert!(matches!(
        bob.process(&deliver(&out[1], "alice.example", "conv-b@bob"))
            .event,
        Event::Message(_)
    ));
    (alice, bob)
}

/// a member re-attributing her message to another member's airdress.
#[test]
fn a_member_cannot_send_as_another_member() {
    let a = Device::new("alice.example", 11);
    let b = Device::new("bob.example", 12);
    let m = Device::new("dana.example", 13);
    let (mut alice, mut bob) = pair(&a, &b);
    let mut dana = m.open();

    // Alice adds Dana (a legitimate member, distinct airdress).
    let kp = dana.key_packages(1).unwrap().remove(0);
    let prepared = alice.prepare_add("conv-b", &[kp]).unwrap();
    alice.confirm_commit("conv-b").unwrap();
    bob.process(&deliver(&prepared.commit, "alice.example", "conv-b@bob"));
    let joined = dana.process(&deliver(
        &prepared.welcome.unwrap(),
        "alice.example",
        "conv-b@m",
    ));
    assert!(matches!(joined.event, Event::Joined { .. }));

    // Dana encrypts claiming to be Bob; the envelope says Bob.
    let forged = dana
        .encrypt("conv-b@m", &text("I am bob"), "bob.example")
        .unwrap();
    let got = alice.process(&deliver(&forged, "bob.example", "conv-b"));
    assert!(
        matches!(&got.event, Event::Failed { reason, retryable: false }
            if reason.contains("does not belong to this group or sender")),
        "expected the binding refusal, got {:?}",
        got.event
    );
}

/// a genuine message from a group the directory no longer maps,
/// delivered under an unrelated conversation, must not be filed there.
#[test]
fn a_superseded_group_is_filed_under_its_own_conversation() {
    let a = Device::new("alice.example", 31);
    let b = Device::new("bob.example", 32);
    let b2 = Device::new("bob.example", 33); // Bob's second device
    let c = Device::new("carol.example", 34);
    let (mut alice, mut bob) = pair(&a, &b);

    // An unrelated conversation with Carol.
    let carol = c.open();
    let kp = carol.key_packages(1).unwrap().remove(0);
    alice
        .establish(
            "conv-c",
            "carol.example",
            &kp,
            &text("hey carol"),
            "alice.example",
        )
        .unwrap();

    // conv-b is re-seated by a rejoin Welcome (a new group G2).
    let g1 = alice.directory().group_for("conv-b").unwrap();
    let mut bob2 = b2.open();
    let akp = alice.key_packages(1).unwrap().remove(0);
    let out = bob2
        .establish(
            "conv-b@bob2",
            "alice.example",
            &akp,
            &text("rejoin"),
            "bob.example",
        )
        .unwrap();
    assert!(matches!(
        alice
            .process(&deliver(&out[0], "bob.example", "conv-b"))
            .event,
        Event::Joined { .. }
    ));
    assert_ne!(alice.directory().group_for("conv-b").unwrap(), g1);
    assert!(alice.directory().conversation_for(&g1).is_none());
    assert!(
        alice.engine().group_epoch(&g1).is_some(),
        "G1 is still held"
    );

    // Bob still writes into G1; the operator files it under conv-c.
    let old = bob
        .encrypt("conv-b@bob", &text("old group"), "bob.example")
        .unwrap();
    let got = alice.process(&deliver(&old, "bob.example", "conv-c"));
    assert!(
        matches!(&got.event, Event::Message(msg)
            if msg.conversation_id == "conv-b" && msg.from_airdress == "bob.example"),
        "a superseded group's late message belongs to its own conversation, got {:?}",
        got.event
    );
}

/// Two changes outstanding: accepting the one shown pins that one.
#[test]
fn accept_pins_the_key_the_person_reviewed() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = PinStore::open(dir.path(), &[3u8; 32]).unwrap();
    s.observe("bob.example", &[1; 32], "t1").unwrap(); // K1 pinned
    s.observe("bob.example", &[2; 32], "t2").unwrap(); // K1 -> K2 shown to the person
    s.observe("bob.example", &[3; 32], "t3").unwrap(); // K1 -> K3 arrives before the tap
    assert!(s.acknowledge("bob.example", &[2; 32], "t4").unwrap()); // the person accepted K2
    assert_eq!(
        s.pinned("bob.example"),
        Some([2; 32]),
        "accept pinned another key"
    );
}

/// A change recorded before a verified pin can no longer be accepted.
#[test]
fn a_verified_pin_resolves_the_changes_before_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = PinStore::open(dir.path(), &[3u8; 32]).unwrap();
    s.observe("bob.example", &[1; 32], "t1").unwrap(); // K1
    s.observe("bob.example", &[2; 32], "t2").unwrap(); // K1 -> K2 (attacker key)
    s.pin_out_of_band("bob.example", &[4; 32], "t3").unwrap(); // verified K4
    let had = s.acknowledge("bob.example", &[2; 32], "t4").unwrap();
    assert!(!had, "a change from before the verified pin was accepted");
    let pinned = s.pinned("bob.example");
    assert_eq!(
        pinned,
        Some([4; 32]),
        "a stale change replaced the out-of-band pin"
    );
}
