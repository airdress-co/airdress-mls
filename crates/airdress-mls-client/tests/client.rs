//! Two and three clients over temporary directories, past the v2
//! cutover: establish, join, talk both ways, add a third member, remove
//! one, and come back from sealed state.

use airdress_mls::MlsEngine;
use airdress_mls::credential::test_support::signed_delegation_json_v2;
use airdress_mls_client::wire::b64_group_id;
use airdress_mls_client::{
    Client, Event, InboundEnvelope, LanePayload, OutboundEnvelope, commit_group_tag,
};
use base64::Engine as _;
use ed25519_dalek::SigningKey;

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
        let root = SigningKey::from_bytes(&[n.wrapping_add(100); 32]);
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
        Client::open(engine, &self.dir.path().join("client"), &self.key).unwrap()
    }
}

/// What the operator would deliver to a recipient for an envelope.
fn deliver(
    out: &OutboundEnvelope,
    from: &str,
    conversation_for_recipient: &str,
) -> InboundEnvelope {
    InboundEnvelope {
        envelope_id: out.idempotency_key.clone(),
        conversation_id: conversation_for_recipient.to_owned(),
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

fn message(event: &Event) -> (String, String) {
    match event {
        Event::Message(m) => (
            m.conversation_id.clone(),
            m.blocks[0]["text"].as_str().unwrap().to_owned(),
        ),
        other => panic!("expected a message, got {other:?}"),
    }
}

#[test]
fn establish_join_and_talk_both_ways_then_restart() {
    let a = Device::new("alice.example", 1);
    let b = Device::new("bob.example", 2);
    let mut alice = a.open();
    let mut bob = b.open();

    let bob_kp = bob.key_packages(1).unwrap().remove(0);
    let out = alice
        .establish(
            "conv-a",
            "bob.example",
            &bob_kp,
            &text("hello bob"),
            "alice.example",
        )
        .unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].envelope_kind, "mls_welcome");
    assert_eq!(out[1].envelope_kind, "mls_application");
    assert_eq!(out[0].target_airdress.as_deref(), Some("bob.example"));

    // Bob's operator files it under Bob's own row for the thread.
    let joined = bob.process(&deliver(&out[0], "alice.example", "conv-b"));
    assert!(joined.ack);
    assert!(
        matches!(joined.event, Event::Joined { ref conversation_id, .. } if conversation_id == "conv-b")
    );
    let first = bob.process(&deliver(&out[1], "alice.example", "conv-b"));
    assert!(first.ack);
    assert_eq!(
        message(&first.event),
        ("conv-b".to_owned(), "hello bob".to_owned())
    );

    let reply = bob
        .encrypt("conv-b", &text("hi alice"), "bob.example")
        .unwrap();
    let got = alice.process(&deliver(&reply, "bob.example", "conv-a"));
    assert_eq!(
        message(&got.event),
        ("conv-a".to_owned(), "hi alice".to_owned())
    );

    // A re-attributed message does not decrypt: the sender is bound.
    let forged = bob
        .encrypt("conv-b", &text("not from alice"), "bob.example")
        .unwrap();
    let refused = alice.process(&deliver(&forged, "mallory.example", "conv-a"));
    assert!(matches!(
        refused.event,
        Event::Failed {
            retryable: false,
            ..
        }
    ));

    // Both come back from sealed state and keep talking.
    drop(alice);
    drop(bob);
    let mut alice = a.open();
    let mut bob = b.open();
    let again = alice
        .encrypt("conv-a", &text("still here"), "alice.example")
        .unwrap();
    let got = bob.process(&deliver(&again, "alice.example", "conv-b"));
    assert_eq!(message(&got.event).1, "still here");

    // Establishing twice is refused rather than founding a second group.
    let kp = bob.key_packages(1).unwrap().remove(0);
    assert_eq!(
        alice.establish("conv-a", "bob.example", &kp, &text("x"), "alice.example"),
        Err(airdress_mls_client::SendError::AlreadyEstablished)
    );
    assert_eq!(
        alice.encrypt("conv-z", &text("x"), "alice.example"),
        Err(airdress_mls_client::SendError::NoGroup)
    );
}

#[test]
fn a_third_member_is_added_hears_the_group_and_is_then_removed() {
    let a = Device::new("alice.example", 11);
    let b = Device::new("bob.example", 12);
    let c = Device::new("alice.example", 13); // a second device of Alice's
    let mut alice = a.open();
    let mut bob = b.open();
    let mut carol = c.open();

    let bob_kp = bob.key_packages(1).unwrap().remove(0);
    let out = alice
        .establish(
            "conv-a",
            "bob.example",
            &bob_kp,
            &text("one"),
            "alice.example",
        )
        .unwrap();
    bob.process(&deliver(&out[0], "alice.example", "conv-b"));
    bob.process(&deliver(&out[1], "alice.example", "conv-b"));

    // An application for a group not yet joined is left for the replay.
    let early = alice
        .encrypt("conv-a", &text("too early"), "alice.example")
        .unwrap();
    let pending = carol.process(&deliver(&early, "alice.example", "conv-a"));
    assert!(!pending.ack);
    assert!(matches!(
        pending.event,
        Event::Failed {
            retryable: true,
            ..
        }
    ));
    // (Bob reads it, so the group stays in step.)
    bob.process(&deliver(&early, "alice.example", "conv-b"));

    // Alice adds her second device.
    let carol_kp = carol.key_packages(1).unwrap().remove(0);
    let prepared = alice.prepare_add("conv-a", &[carol_kp]).unwrap();
    assert_eq!(prepared.commit.envelope_kind, "mls_commit");
    let group = alice.directory().group_for("conv-a").unwrap();
    assert_eq!(
        prepared.commit.commit_group.as_deref(),
        Some(commit_group_tag(&group).as_str())
    );
    assert_eq!(prepared.commit.commit_from_epoch, Some(1));
    alice.confirm_commit("conv-a").unwrap();

    let applied = bob.process(&deliver(&prepared.commit, "alice.example", "conv-b"));
    assert!(applied.ack);
    match &applied.event {
        Event::Membership { added, epoch, .. } => {
            assert_eq!(added.len(), 1);
            assert_eq!(*epoch, 2);
        }
        other => panic!("expected a membership change, got {other:?}"),
    }
    // The same commit again (a replay) is older than the group: ignored.
    let replayed = bob.process(&deliver(&prepared.commit, "alice.example", "conv-b"));
    assert!(replayed.ack);
    assert!(matches!(replayed.event, Event::Ignored { .. }));

    let welcome = prepared.welcome.expect("an add carries a welcome");
    let joined = carol.process(&deliver(&welcome, "alice.example", "conv-a"));
    assert!(matches!(joined.event, Event::Joined { .. }));

    let from_bob = bob
        .encrypt("conv-b", &text("to both of you"), "bob.example")
        .unwrap();
    assert_eq!(
        message(
            &alice
                .process(&deliver(&from_bob, "bob.example", "conv-a"))
                .event
        )
        .1,
        "to both of you"
    );
    assert_eq!(
        message(
            &carol
                .process(&deliver(&from_bob, "bob.example", "conv-a"))
                .event
        )
        .1,
        "to both of you"
    );

    // Alice removes it again; Carol learns she was removed.
    let carol_identity = alice
        .engine()
        .group_members(&group)
        .unwrap()
        .into_iter()
        .map(|m| m.identity)
        .find(|id| id.ends_with(b"device-13"))
        .expect("carol's leaf");
    let removal = alice.prepare_remove("conv-a", &[carol_identity]).unwrap();
    assert!(removal.welcome.is_none());
    alice.confirm_commit("conv-a").unwrap();
    let out = carol.process(&deliver(&removal.commit, "alice.example", "conv-a"));
    assert!(out.ack);
    assert_eq!(
        out.event,
        Event::Removed {
            conversation_id: "conv-a".to_owned()
        }
    );
    assert!(carol.directory().group_for("conv-a").is_none());
    assert!(matches!(
        bob.process(&deliver(&removal.commit, "alice.example", "conv-b")).event,
        Event::Membership { ref removed, .. } if removed.len() == 1
    ));
    let _ = b64_group_id(&group);
}

#[test]
fn an_aborted_commit_leaves_the_group_where_it_was() {
    let a = Device::new("alice.example", 21);
    let b = Device::new("bob.example", 22);
    let c = Device::new("carol.example", 23);
    let mut alice = a.open();
    let bob = b.open();
    let carol = c.open();
    let kp = bob.key_packages(1).unwrap().remove(0);
    alice
        .establish("conv", "bob.example", &kp, &text("x"), "alice.example")
        .unwrap();
    let group = alice.directory().group_for("conv").unwrap();
    let before = alice.engine().group_epoch(&group).unwrap();
    let carol_kp = carol.key_packages(1).unwrap().remove(0);
    alice.prepare_add("conv", &[carol_kp]).unwrap();
    alice.abort_commit("conv").unwrap();
    assert_eq!(alice.engine().group_epoch(&group).unwrap(), before);
}

#[test]
fn kinds_this_client_does_not_handle_are_acknowledged() {
    let a = Device::new("alice.example", 31);
    let mut alice = a.open();
    for kind in ["rejoin_request", "audio_burst", "mls_proposal"] {
        let env = InboundEnvelope {
            envelope_id: "e".into(),
            conversation_id: "c".into(),
            envelope_kind: kind.into(),
            from_airdress: "x.example".into(),
            ciphertext: vec![1, 2, 3],
            commit_from_epoch: None,
            duration_ms: None,
            received_at: None,
        };
        let p = alice.process(&env);
        assert!(p.ack, "{kind}");
        assert!(matches!(p.event, Event::Ignored { .. }), "{kind}");
    }
}

#[test]
fn the_shared_vectors_hold() {
    let v: serde_json::Value =
        serde_json::from_str(airdress_mls_client::vectors::COMMIT_GROUP).unwrap();
    let cases = v["vectors"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let gid = base64::engine::general_purpose::STANDARD
            .decode(case["group_id_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            commit_group_tag(&gid),
            case["commit_group"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }

    let v: serde_json::Value =
        serde_json::from_str(airdress_mls_client::vectors::LANE_PAYLOAD).unwrap();
    let cases = v["vectors"].as_array().unwrap();
    assert!(cases.len() >= 6);
    for case in cases {
        let got = LanePayload::decode(case["plaintext"].as_str().unwrap().as_bytes());
        match &case["decodes_to"] {
            serde_json::Value::Null => assert!(got.is_err(), "{} must be refused", case["name"]),
            want => {
                let got = got.unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
                assert_eq!(
                    serde_json::to_value(&got).unwrap(),
                    *want,
                    "{}",
                    case["name"]
                );
            }
        }
    }
}
