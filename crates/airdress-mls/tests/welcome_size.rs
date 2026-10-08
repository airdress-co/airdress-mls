//! How big a group conversation's Welcome is (SPEC-145 145-G1.14, NFR-5,
//! design D-11).
//!
//! A Welcome carries the whole ratchet tree — one leaf per device, each
//! with its credential, and an Airdress credential carries the device's
//! root-signed delegation — plus the group context with its four group
//! extensions. It travels as one envelope, and the operator refuses a
//! Welcome over its `max_welcome_bytes` (147 456 by default; its own limit
//! by the owner's ruling of 2026-10-09, as audio has one). So the number of
//! leaves a group may hold is set by this measurement against that limit,
//! with 20 % headroom.
//!
//! The leaves are realistic: hosted airdress names (`<uuid>.a.airdr.es`),
//! UUID device ids, a device label, and delegations shaped as the phone
//! mints them. Welcome bytes grow linearly in the leaf count, so the leaf
//! cap is read off the measured per-leaf cost and checked by building a
//! Welcome at the cap itself.
//!
//! A measurement, not a check that runs on every push: it builds groups of
//! up to 128 engines and takes minutes. Run it when the credential, the
//! extensions or `mls-rs` change, and update `GROUP_LEAF_CAP` from it:
//!
//! ```bash
//! cargo test --release -p airdress-mls --test welcome_size -- --ignored --nocapture
//! ```

#![expect(
    clippy::print_stdout,
    clippy::tests_outside_test_module,
    reason = "a measurement prints its table, from an integration test file"
)]

use airdress_mls::MlsEngine;
use airdress_mls::group_context::{
    GroupExtensions, GroupPolicy, GroupProfile, GroupRoles, GroupSequencer,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Map, Value, json};

/// The operator's default `chat.limits.max_welcome_bytes`.
const ENVELOPE_LIMIT: usize = 147_456;

/// NFR-5: the Welcome at the cap fits the limit with 20 % headroom.
const BUDGET: usize = ENVELOPE_LIMIT * 80 / 100;

fn airdress(n: usize) -> String {
    format!(
        "{:08x}-1b2d-4e4b-9e53-1a8c5dfe{n:04x}.a.airdr.es",
        0x019e_37b4 + n
    )
}

fn delegation(root: &SigningKey, airdress: &str, session_pk: &[u8; 32], device: &str) -> String {
    let mut obj = Map::new();
    obj.insert("airdress".into(), json!(airdress));
    obj.insert("device_label".into(), json!("Galaxy S23"));
    obj.insert(
        "device_session_public_key".into(),
        json!(URL_SAFE_NO_PAD.encode(session_pk)),
    );
    obj.insert("device_id".into(), json!(device));
    obj.insert("expires_at".into(), json!("2027-04-06T12:34:56Z"));
    obj.insert("issued_at".into(), json!("2026-10-08T12:34:56Z"));
    obj.insert("role".into(), json!("human_held"));
    let canonical = airdress_mls::canonical::canonical_delegation_bytes(&obj).unwrap();
    obj.insert(
        "signature".into(),
        json!(URL_SAFE_NO_PAD.encode(root.sign(&canonical).to_bytes())),
    );
    serde_json::to_string(&Value::Object(obj)).unwrap()
}

struct Device {
    engine: MlsEngine,
    _dir: tempfile::TempDir,
}

fn device(person: usize, nth: usize) -> Device {
    let dir = tempfile::tempdir().unwrap();
    let root = SigningKey::from_bytes(&[u8::try_from(person % 251).unwrap() + 1; 32]);
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(person as u64).to_be_bytes());
    seed[8..16].copy_from_slice(&(nth as u64).to_be_bytes());
    seed[31] = 1;
    let session_pk = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let who = airdress(person);
    let device_id = format!("5b1f5a68-1b2d-4e4b-{person:04x}-{nth:012x}");
    let engine = MlsEngine::from_seed(
        &who,
        &seed,
        &root.verifying_key().to_bytes(),
        &delegation(&root, &who, &session_pk, &device_id),
        dir.path().to_str().unwrap(),
        &[0x5a; 32],
    )
    .unwrap();
    Device { engine, _dir: dir }
}

/// The Welcome a creator's first commit produces for a group of `persons`
/// persons with `devices` devices each (the creator's own other devices
/// included), in bytes.
fn welcome_bytes(persons: usize, devices: usize) -> usize {
    let mut creator = device(0, 0);
    let creator_pin = airdress(0);
    let ext = GroupExtensions {
        profile: GroupProfile {
            v: 1,
            title: "x".repeat(100),
            avatar_sha256: Some("ab".repeat(32)),
        },
        roles: GroupRoles {
            v: 1,
            admins: vec![creator_pin.clone()],
            join_order: vec![creator_pin],
        },
        policy: GroupPolicy::creation_default(),
        sequencer: GroupSequencer {
            v: 1,
            operator_fqdn: airdress(0),
            kid: "k-0011223344556677".into(),
        },
    };
    let group = creator.engine.create_group_with_extensions(&ext).unwrap();
    for person in 0..persons {
        for nth in 0..devices {
            if person == 0 && nth == 0 {
                continue;
            }
            let joiner = device(person, nth);
            let kp = joiner.engine.generate_key_package().unwrap();
            creator.engine.propose_add(&group, &kp).unwrap();
        }
    }
    let outcome = creator.engine.commit_pending(&group).unwrap();
    outcome.welcome.map_or(0, |w| w.len())
}

#[test]
#[ignore = "a measurement of minutes; run with --ignored when the leaf format changes"]
fn the_welcome_at_the_cap_fits_the_envelope_with_headroom() {
    use airdress_mls::group_context::GROUP_LEAF_CAP;
    println!("persons devices leaves welcome_bytes fits_with_headroom");
    let mut samples = Vec::new();
    for persons in [3, 8, 16, 32] {
        for devices in [1, 2, 4] {
            let leaves = persons * devices;
            if leaves > GROUP_LEAF_CAP {
                // The engine refuses to build it; the size is extrapolated
                // below from the ones it builds.
                println!("{persons:7} {devices:7} {leaves:6}   (over the cap)");
                continue;
            }
            let bytes = welcome_bytes(persons, devices);
            println!(
                "{persons:7} {devices:7} {leaves:6} {bytes:13} {}",
                bytes <= BUDGET
            );
            samples.push((leaves, bytes));
        }
    }
    // Per-leaf cost from the two extremes, rounded up so the cap errs small.
    let (l0, b0) = samples.iter().min_by_key(|s| s.0).copied().unwrap();
    let (l1, b1) = samples.iter().max_by_key(|s| s.0).copied().unwrap();
    let per_leaf = (b1 - b0).div_ceil(l1 - l0);
    let fixed = b0.saturating_sub(per_leaf * l0);
    let measured_cap = (BUDGET - fixed) / per_leaf;
    println!(
        "per leaf {per_leaf} B, fixed {fixed} B, budget {BUDGET} B -> leaf cap {measured_cap}; \
         32 persons x 2 devices ~ {} B, x 4 ~ {} B",
        fixed + 64 * per_leaf,
        fixed + 128 * per_leaf
    );
    assert!(
        GROUP_LEAF_CAP <= measured_cap,
        "GROUP_LEAF_CAP {GROUP_LEAF_CAP} is more than the {measured_cap} measured to fit"
    );

    // Next to the cap, built: 27 persons with 5 devices each (135 leaves,
    // within the 32-person cap).
    let at_cap = welcome_bytes(GROUP_LEAF_CAP / 5, 5);
    println!("built at {} leaves -> {at_cap} B", GROUP_LEAF_CAP / 5 * 5);
    assert!(at_cap <= BUDGET, "{at_cap} B at the cap is over {BUDGET} B");
}
