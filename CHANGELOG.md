# Changelog

What changed in each tagged release, for the three consumers: the phone
(airdress-chat, through the C ABI in `airdress-mls-ffi`), the operator and
airdress-cli (both linking `airdress-mls` as a Rust library at a tag).

## Conventions

- Every release has a **Breaking** section, first, even when it says
  "Nothing". It lists what a consumer has to change when it moves its pin:
  a Rust API that went away or changed shape, a C export whose behaviour a
  caller can observe differently, or a refusal where there used to be an
  answer. Everything else goes under Added, Changed or Fixed.
- The C ABI is additive only: an export is never removed or renamed, and
  a result struct never changes layout. A change to the ABI is a change to
  `crates/airdress-mls-ffi/symbols.txt` in the same commit.
- `vectors/` are append-only, so a vector change is always "Added".
- Consumers pin a tag, never a branch (rust guide R-API-6).
  `cargo-semver-checks` runs in CI against the base revision.

## Unreleased

### Breaking

- **A committing device refuses a group conversation past 60 leaves**
  (`group_context::GROUP_LEAF_CAP`), as it already refused one past 32
  persons, with the same `GroupRule::TooManyPersons` ("that would make the
  group too big"). Only the sending side holds it; a receiver applies a
  bigger commit. 60 is what fits the operator's default 65 536-byte
  envelope with 20 % headroom: measured at 854 bytes a leaf plus 640 fixed
  (SPEC-145 145-G1.14, `tests/welcome_size.rs`, run with `--ignored`).
  32 persons fit at one device each and not at two (~55.3 KB).

### Added

- `group_context::GROUP_LEAF_CAP` and the measurement that sets it.

## v0.4.0 — 2026-10-09

A third credential form, for every person of an airdress who is not its
owner.

### Breaking

- **`IdentityVersion` has a third variant, `V3`.** An exhaustive `match`
  on it needs the arm. `parse_identity` now accepts `"v": 3` (it used to
  refuse it as an unknown version) and holds it to its fields: a `v: 3`
  without `delegation`, `root_public_key` or `airdress` is still an error,
  never a legacy identity.
- **`RootKeyLookup` is asked for a pin subject, not always an airdress.**
  The signature is unchanged, and for every `v: 1` and `v: 2` leaf the
  argument is the bare airdress exactly as before. For a `v: 3` leaf it is
  `airdress ‖ 0x1F ‖ person_id`. A host that does not resolve that form
  answers `None` and the leaf is refused (`RootKeyUnavailable`), which is
  the intended failure for a host that has not learned about persons; it
  must not strip the suffix and answer with the airdress root. The C
  callback registered with `airdress_mls_set_root_key_lookup` receives
  the same string.
- **A `Remove` is authorised per person once a `v: 3` leaf is involved.**
  Inside one airdress, a device may remove only leaves with its own pin
  subject: the owner's devices remove the owner's, a household member's
  devices remove that member's. A member can never remove an owner
  device (revoked or not), and the owner can no longer remove a member's
  live device. The one exception: a `v: 3` leaf whose `device_id` this
  device's check-5 revocation lookup answers `Revoked` for may be removed
  by any device of the airdress — the witness is each device's own
  lookup, on the send and the receive side, so a commit removing a
  device the receiver holds live is refused (and a receiver with a stale
  view refreshes and processes the same commit again). Where there used
  to be an answer there is now a refusal, on `propose_remove` (the
  message is the rule's sentence) and on `process_commit` /
  `process_proposal`. Groups with no `v: 3` leaf are unchanged: the
  airdress rule is still the whole rule there, checked first.
- **`MlsRulesError` has a third variant, `CrossPersonRemoval { airdress }`.**
  An exhaustive `match` on it needs the arm. It carries the airdress only,
  never a `person_id`.
- **`AirdressMlsRules::new()` admits no revoked exception.** It has no
  revocation lookup to read, so it refuses every removal of another
  person's leaf. `MlsEngine` now builds its rules with
  `AirdressMlsRules::sharing_revocation_with(&provider)`; a host that
  builds its own `mls-rs` client (the operator's agent does) and wants a
  household peer's commit removing a revoked person to apply must do the
  same, or that commit is refused there.
- **`MlsRulesError` has a fourth variant, `Group(GroupRule)`**: a group
  conversation's rules refused the proposal set. An exhaustive `match`
  needs the arm.
- **A group conversation has its own rule set**, which replaces the
  per-airdress removal rule there and only there (SPEC-145 design D-5).
  A group conversation is one whose context carries all four group
  extensions; every other group is unchanged. In one, an admin may remove
  any person's devices (across airdresses), a member only their own; a
  person's devices are added only by that person; a new person only by an
  admin unless the policy says otherwise; the policy and the sequencer are
  the admins'; the title and picture follow the policy; and after every
  commit an admin is still in the group, so a commit removing the last one
  must carry the forced promotion of the earliest-joined person. A commit
  breaking any of them is refused on `commit_pending` and on
  `process_commit`, naming the rule.
- **Every engine advertises the four group extension types** in its leaf
  capabilities, so a key package from this version differs from one made
  by an earlier version. RFC 9420 lets a group context carry an extension
  only when every leaf advertises it, so an older engine cannot be added
  to a group conversation.

### Added

- **`v: 3`**: a delegation that carries `person_id` (with `device_id` and
  `expires_at`, as `v: 2`), signed by that person's own root rather than
  the airdress root. `AirdressIdentity::from_delegation` infers it from
  `person_id` alone, so a delegation naming a person without the other
  two fields is a malformed `v: 3`, never a `v: 1`. Member identity:
  `airdress ‖ 0x1F ‖ person_id ‖ 0x1F ‖ device_id`, which cannot equal
  any `v: 1` or `v: 2` member identity. Checks 1, 3, 4 and 5 apply as to
  `v: 2` (revocation stays keyed on `device_id`); check 2 looks the root
  up under the pin subject. `valid_successor` never accepts a successor
  of another version or another `person_id`. Past the v2 cutover `v: 3`
  is a live form.
- `AirdressIdentity::pin_subject`, `AirdressIdentity::person_id`,
  `credential::pin_subject_for_person`, `credential::split_pin_subject`
  and `credential::PERSON_ID_FIELD`.
- `test_support::signed_delegation_json_v3`.
- `AirdressMlsRules::sharing_revocation_with(&AirdressIdentityProvider)`:
  the rules, reading the revocation witness from the provider's check-5
  lookup, whenever the host registers it.
- Group conversations (SPEC-145): `group_context` (the four extensions
  `airdress_group_profile`, `_roles`, `_policy`, `_sequencer` in the
  private-use range `0xF5A1`–`0xF5A4`, JSON bodies with a version field;
  `GroupExtensions`, `canonical_join_order`, `forced_roles`,
  `GROUP_MAX_PERSONS` = 32), `group_rules` (`GroupRule`), and on
  `MlsEngine`: `create_group_with_extensions`, `group_extensions`,
  `propose_extensions`, `propose_self_remove`, `group_roster`
  (`RosterEntry`), plus `engine::message_epoch`.
- Six C exports for them: `airdress_mls_group_create_with_extensions`,
  `airdress_mls_group_extensions`, `airdress_mls_propose_extensions`,
  `airdress_mls_propose_self_remove`, `airdress_mls_group_roster`,
  `airdress_mls_message_epoch`. JSON in and out; no result struct changes.
- Vector `person-v3-delegation`, carrying an `identity` block with the
  expected `pin_subject` and `member_identity`, so every implementation
  checks the same strings.

### Changed

- The C ABI is unchanged: no export added, renamed or re-laid-out. A host
  makes a `v: 3` device by handing `airdress_mls_create_engine_from_seed`
  a delegation that carries `person_id` and the person's own root public
  key.
- `airdress-mls-client`'s `PinStore` documents that its keys are pin
  subjects; pins already written are under the bare airdress, which is
  the owner's subject, so nothing moves.

### Not changed, and worth knowing

- The C ABI: no export added. The revocation witness is the lookup a host
  already registers with `airdress_mls_set_revocation_lookup`.
- `ErrorCode`: a refused removal is still `Engine` (1) across the C ABI.
  A host that refuses an inbound commit tells this refusal apart by the
  message, refreshes its revocation state, and retries the same commit.

## v0.3.0 — 2026-10-07

Everything since `5cf9036` (0.2.0, the revision the operator pins).

### Breaking

Fail closed (owner decision, 2026-10-07):

- **Past the v2 cutover, verification refuses until a revocation lookup
  is registered.** An `AirdressIdentityProvider` (and so an `MlsEngine`)
  that has entered `set_v2_cutover` answers every leaf with
  `CredentialVerifyError::RevocationUnavailable` until
  `set_revocation_lookup` has been called, in either order. Before, check
  5 was skipped for every leaf, silently, and a revoked device kept its
  seat. The two C switches are coupled the same way:
  `airdress_mls_set_v2_cutover` needs `airdress_mls_set_revocation_lookup`.
  **A host that enters the cutover must now register a lookup**, or no
  group work verifies.
- **`credential::verify_identity` is renamed
  `verify_identity_without_revocation`**, so the name says it skips
  check 5. Same signature and behaviour otherwise.
- **A clock before 1970 refuses.** `SystemClock` used to read such a
  clock as 0, which put every expiry in the future. Verification now
  reads the new `Clock::now_unix_seconds_checked` (default: `Some` of
  `now_unix_seconds`, so existing `Clock` implementations are unchanged),
  and `None` refuses any delegation with an expiry, every `v: 2` one
  included, with the new variant `CredentialVerifyError::ClockUnavailable`.
  An exhaustive `match` on `CredentialVerifyError` needs the arm.
- **`airdress-mls-ffi` no longer re-exports `airdress_mls::*`.** Its
  contract is the C ABI; a Rust consumer depends on `airdress-mls`.

Earlier in this release:

- **The FFI's pointer-taking exports are `unsafe extern "C"`.** The C
  symbols and their signatures are unchanged, so the Dart bindings need
  nothing; the change is that each now documents the contract its caller
  keeps (`# Safety`), which is what made the rest of this release's FFI
  checks possible.
- **The FFI refuses inputs it used to read.** A null pointer with a
  non-zero length, or a length above `isize::MAX`, is now an error result
  (code `InvalidArgument`) instead of undefined behaviour. A null pointer
  with length 0 is the empty input.
- **The integer FFI exports have a panic answer.** A panic inside an
  export is caught: the `i32` exports (`set_root_key_lookup`,
  `set_revocation_lookup`, `set_v2_cutover`, `is_v2_cutover`) return `-3`,
  the `i64` ones (`key_package_pool_count`, `confirm_commit`,
  `abort_commit`, `group_epoch`) return `-2`, their existing failure value,
  because the app reads any other negative number as a count or an epoch.
  A null lookup callback is `-1`.
- **A group record with trailing bytes, or an epoch count its bytes cannot
  hold, no longer decodes.** `encode` never wrote either; both were found
  by the new fuzz target.

### Added

- `airdress_mls_mint_agent_delegation` (C) and `delegation` (Rust): the
  phone signs a thirty-day delegation for an agent device with the root,
  which never leaves it.
- `airdress-mls-client`, a new crate: the envelope pump's decisions, the
  conversation-to-group directory and the peer-root pin store, in Rust,
  with no network. Vectors `lane_payload.json` and `commit_group.json`.
- Stable error codes: `ErrorCode` (`Engine` 1, `InvalidArgument` 2,
  `InvalidHandle` 3, `Internal` 4, `EpochUnavailable` 5,
  `BindingRequired` 6), `EngineError::code()`, and the export
  `airdress_mls_error_code(error)`, read before the error string is freed.
  Code 5 is the trimmed-epoch case the app used to recognise by the
  sentence "older than the keys still on this device".
- `engine::message_group_id`, the parse `airdress_mls_message_group_id`
  now calls.
- Vector `nested-object-keys-unsorted-in-source`.
- `Debug` for `MlsEngine` (public key only), `StartGroupOutcome` and the
  client's `Client`, `Directory` and `PinStore` (no content).

### Changed

- Every FFI export runs under `catch_unwind`: a panic, here or inside
  mls-rs on hostile input, is an error result (`Internal`) instead of
  aborting the app. A build with `panic = "abort"` is refused at compile
  time. A poisoned engine table is recovered.
- Secrets are wiped on drop: the decoded group record and each epoch
  entry, the client's sealed-file key, and the FFI's copies of the session
  seed and state key.
- The rust guide's `[workspace.lints]` apply, with `unsafe_code` forbidden
  everywhere except the FFI module.
- `airdress-mls-ffi` no longer depends on `mls-rs` directly.

### Fixed

- Thirty FFI call sites handed caller pointers to `slice::from_raw_parts`
  without a null or length check.
- A panic while the engine table was locked made every later call abort
  the app.

## v0.2.0

The engine split from its C ABI into `airdress-mls` and
`airdress-mls-ffi`, with licences, an audit, cargo-deny and CI for a
public repository. Not tagged; the operator pins `5cf9036`.
