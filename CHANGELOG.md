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

- Nothing.

## v0.7.0 — 2026-11-04

### Breaking

- **C ABI change, in place: `AirdressRevocationLookupFn`** (the callback
  `airdress_mls_set_revocation_lookup` takes) is now
  `int32_t (*)(const char *subject, const char *device_id)`. This breaks
  the additive-only rule for the C ABI on purpose: the app must change
  its callback together with the pin. `subject` is the leaf's pin
  subject, the same string `AirdressRootKeyLookupFn` receives for that
  leaf (the bare airdress for an owner's device,
  `airdress ‖ 0x1F ‖ person_id` for another person's); the return values
  are unchanged (`1` active, `0` revoked, anything else cannot answer).
  A `device_id` is unique only under one pin subject, so the host keys
  its revocation state by the pair.
- `airdress_mls::credential::RevocationLookup::device_status` takes the
  pin subject too: `device_status(subject, device_id)`, and the closure
  form is `Fn(&str, &str) -> Option<DeviceStatus>`. Check 5 and the
  removal rule's revocation witness both ask for the pair, so revoking
  one person's device no longer answers for another person's device of
  the same `device_id`.
- `EngineError` has two new variants, `RevocationViewStale` and
  `Storage`, each with its own `ErrorCode` (values `7` and `8`, read
  through `airdress_mls_error_code`); an exhaustive match must name them.
  `MlsEngine::process_welcome` returns `Result<_, EngineError>` instead of
  `Result<_, String>`; a Welcome naming no held key package is
  `EngineError::Other(WELCOME_KEY_PACKAGE_NOT_FOUND)`, as before in
  substance.
- New answers where there used to be another:
  - `MlsEngine::process_commit` (and `airdress_mls_process_commit`)
    refuses a received commit that removes another person's device this
    device does not hold revoked with `RevocationViewStale` (code 7), not
    the general engine error. Refresh the revocation state and process
    the same commit again. In a group conversation that refusal is
    `GroupRule::RemoveOther`, and stays the general engine error;
  - `process_welcome`, `decrypt`, `decrypt_with_sender` and
    `process_commit` (and their C exports) answer `Storage` (code 8) when
    the new group state could not be written. Nothing was kept, and the
    same input succeeds once storage does;
  - the client leaves an envelope whose state write failed unacknowledged
    (`Failed { retryable: true }`) on every path: Welcome, application
    and commit. Before, it acknowledged it, as `Failed`, `RejoinNeeded`
    or a not-retryable `Failed`, and the envelope was lost;
  - the client leaves a commit refused with `RevocationViewStale`
    unacknowledged (`Failed { retryable: true }`) for up to
    `client::MAX_DEFERRALS` deliveries, counted across restarts, and only
    then asks to rejoin (`RejoinNeeded`). Before, it asked to rejoin at
    once.
- `airdress_mls_client::pins::PinStore::acknowledge` takes the key the
  person accepted: `acknowledge(airdress, observed, now)`. It adopts that
  key only if a change from the current pin to it was recorded. Recorded
  changes stay as history (`changes()`); what can still be accepted is
  `pending_changes()`.
- `airdress_mls_client::directory::Directory::record_replacing` returns
  `Result<bool, _>`: `false`, changing nothing, when the group belongs to
  another conversation.
- `GroupRule` has new variants: `NotAGroup`, `AdminNotInGroup`,
  `ChangeOtherExtensions` and `UnsupportedProposal`.
- New refusals, where there used to be an answer:
  - a one-to-one, self or household group refuses a commit that adds the
    group conversation extensions, in full or in part (`NotAGroup`);
  - past the cutover, `decrypt`, `decrypt_with_sender` and the bound C
    exports refuse a message whose authenticated sending leaf does not
    belong to the `from_airdress` it is bound to, with the binding error;
  - the client reports a Welcome as `Failed` when its group already
    belongs to another conversation;
  - the client files an application message by its own record of the
    group, never by the envelope's conversation id: a group a rejoin
    superseded still belongs to its conversation
    (`Directory::conversation_of_message`), and a message for a group no
    conversation holds is ignored;
  - `airdress_mls_generate_key_packages` refuses a `count` above 256 with
    `InvalidArgument`, before the engine is locked. A larger count used to
    be attempted, and a huge one aborted the process.
  - in a group conversation, a commit is refused when an admin its roles
    name leaves the group in it, or comes back in it (`AdminNotInGroup`):
    a commit that removes an admin carries the roles without them, and so
    does one that adds back a person the roles still name. A person
    removed as an admin and added back is a member, not an admin. An
    admin the roles already named while absent before the commit (a
    state earlier releases could leave) is tolerated, so such a group
    keeps taking commits; the next roles change drops them;
  - in a group conversation, a commit carrying a `ReInit`, `PreSharedKey`,
    `ExternalInit` or custom proposal is refused (`UnsupportedProposal`),
    and so is a `ReInit` in a one-to-one, self or household group;
  - in a group conversation, a member who is not an admin may not change a
    context extension outside the four group extensions
    (`ChangeOtherExtensions`).
  - `MlsEngine::commit_pending` (and `airdress_mls_commit_pending`)
    refuses proposals staged at an earlier epoch than the group is at, and
    drops them: a `Remove` names a leaf index, which can hold another
    member by then. Propose again from a fresh read of the tree;
  - `MlsEngine::confirm_commit` (and `airdress_mls_confirm_commit`)
    refuses, and drops the held commit, when the group has moved to
    another epoch since the commit was built.
  - the client acknowledges an application or commit for a group this
    device has not joined as `Failed` (not retryable) on its
    `client::MAX_DEFERRALS`th delivery (8), counted across restarts,
    where it used to leave it for a replay on every connection.
  - an identity whose `airdress` is not the `airdress` inside its signed
    delegation, or whose delegation names none, is refused
    (`CredentialVerifyError::Malformed`); `MlsEngine::from_seed` and
    `airdress_mls_create_engine_from_seed` refuse such a delegation for
    the engine's own identity;
  - past the v2 cutover, a leaf is refused with `RootKeyUnavailable`
    until a root-key lookup is registered (`set_root_key_lookup`,
    `airdress_mls_set_root_key_lookup`), as it already was for the
    revocation lookup. A host that enters the cutover registers both.
- `airdress_mls::rules::MlsRulesError::CrossPersonRemoval` has a second
  field, `revocable: bool`: whether the revocation witness decided the
  refusal. A received commit is `RevocationViewStale` only when it is
  `true`; a removal no revocation state admits (an owner device, by a
  household member's device) stays the general engine error, and the
  client asks to rejoin at once.
- `MlsEngine::confirm_commit` returns `Result<u64, EngineError>` instead
  of `Result<u64, String>`: a failed write is `EngineError::Storage`.
  `Client::confirm_commit` reports it as `SendError::Storage`, whose
  message now says the device's state could not be written (the
  directory's or the engine's). `airdress_mls_confirm_commit` is
  unchanged (`-2`).

### Added

- `EngineError::RevocationViewStale`, `EngineError::Storage`,
  `ErrorCode::RevocationViewStale` (7) and `ErrorCode::Storage` (8).
- `PinStore::pending_changes()`.
- `Directory::conversation_of_message()`.
- `MlsEngine::discard_staged()`: drop what is staged for a group without
  committing.
- `storage::INTERRUPTED_WRITE_AGE` (10 minutes).

### Changed

- **A held commit is confirmed onto the group as it is on disk then.**
  `commit_pending` keeps the new epoch's secrets rather than a copy of the
  group, so a message decrypted while the commit waits leaves its
  key used after `confirm_commit`, instead of the copy taken at build time
  restoring it. Messages of the old epoch keep decrypting meanwhile.
- `MlsEngine::abort_commit` drops what is staged for the group even when
  no commit is pending (it still answers that nothing was pending).
- `Client::prepare_add` and `Client::prepare_remove` stage a batch all or
  nothing: when one item is refused, none of the batch is left for the
  next commit.
- `MlsEngine::from_seed` deletes pooled key packages whose leaf does not
  advertise the group extension types, both halves, and makes one
  replacement for each, so `stored_key_packages` republishes only packages
  a group conversation can add. A Welcome built from a deleted package
  answers `WELCOME_KEY_PACKAGE_NOT_FOUND`, which the client turns into a
  rejoin request.
- `client::MAX_DEFERRALS` and `pins::MAX_CHANGES_PER_PIN`.
- `PinStore::changes()` keeps the newest `MAX_CHANGES_PER_PIN` (16)
  changes recorded against each pinned key of an airdress; a newer one
  drops the oldest.
- `PinStore::observe` writes nothing on a match: `last_seen` reaches the
  disk with the next write that changes something else.
- The client calls `airdress_mls::engine::message_group_id` instead of a
  copy of its own, and no longer depends on `mls-rs` directly.

### Fixed

- `crates/airdress-mls-ffi/build-native.sh` builds the phone targets:
  - `ios` produces the static library (`libairdress_mls_ffi.a`) the app
    links, for the device and the simulator, and no longer a `.dylib`;
  - `android` links with the NDK's clang wrapper (`ANDROID_NDK_HOME` or
    `ANDROID_NDK_ROOT`, API level `ANDROID_API_LEVEL`, default 21) and
    says so when no NDK is found;
  - each target is added to the pinned toolchain before it is built, and
    a build that produced no library fails instead of reporting success.
- A device committing in a group conversation adds the roles change its
  commit needs: the roles without an admin it removes, or the forced
  promotion when the last admin leaves. Before, every commit after the
  last admin's leave failed with `NoAdminLeft` until somebody staged the
  promotion by hand.
- An unreadable proposed change to the group extensions, held by
  reference, is left out of this device's next commit instead of failing
  it, as every other refused by-reference proposal already was.
- The person and device caps refuse only a commit that grows the group
  past them. A group already past a cap still takes a removal, a key
  rotation or a settings change.
- `Directory` and `PinStore` write a change before it takes effect, so a
  failed write leaves memory as it was and the envelope behind it is
  judged against the same state when it is replayed (a Welcome, a
  self-removal, a first pin).
- A Welcome the engine joined from, whose directory entry could not be
  written, is filed when it is replayed, or when a message for its group
  arrives, instead of failing on its spent key package. This holds within
  one process; after a restart such a Welcome asks to rejoin.
- `storage::write_file_atomically` and `storage::remove_interrupted_writes`:
  the temp-file, fsync, rename and directory-fsync write both crates'
  sealed files now use, and the cleanup of temp files a crash left.
- A device removed from a group and added back to the same group id
  joins it afresh: the Welcome replaces the group's stored record instead
  of merging into it. Before, the epochs of its earlier membership stayed
  on disk, and the first commit after its return was refused for an
  unexpected epoch (`RejoinNeeded`).
- A sealed write that fails after creating its temp file removes it, and
  `SealedStore::open` removes temp files a crashed write left behind; each
  held a whole sealed item. Sealed files are created mode 0600 on Unix.
- A consumed key package loses its public half before its private half,
  and `stored_public_with_ids` (and so `stored_public_messages`) no longer
  returns a public half whose private half is gone, so an interrupted
  delete can no longer get a used package published again.
- The client's sealed files (the directory and the pin store) are written
  through the same helper: the directory is fsynced after the rename, a
  failed write removes its temp file, and opening removes temp files an
  interrupted write left (including the `.partial` file earlier versions
  wrote).
- The credential chain itself refuses a `device_id` carrying the
  identity separator (`0x1F`), as `Malformed`, as it already did for the
  airdress and `person_id`, instead of relying on the member identity
  being computed afterwards.
- `MlsEngine::confirm_commit` (and `airdress_mls_confirm_commit`) keeps
  the held commit when loading the group, applying the commit or writing
  the new state fails, so the same call succeeds once storage does.
  Before, the held commit was dropped first, and with it the only copy of
  the secrets of an epoch the operator had already accepted. A commit the
  group has moved past is still dropped.
- Opening a store (`SealedStore::open`, the client's sealed files)
  removes only temp files no write in progress can own: the process the
  name records is not running (where `/proc` can say so, never this
  process), or the file is older than `storage::INTERRUPTED_WRITE_AGE`.
  Nothing locks a state directory, and removing every `*.tmp-*` file made
  the rename of a second engine's write in progress fail.
- The client's count of envelopes left for a replay never drops a count
  to make room. When its 256 places are full, a count not delivered for a
  week is dropped; when none is, the new envelope is ended at once
  (`Failed { retryable: false }` for a group this device has not joined,
  `RejoinNeeded` for a commit refused for the revocation view). Before,
  the oldest count was dropped, so a stream of envelopes for groups never
  joined kept every count below `MAX_DEFERRALS` and no bound ever fired.
- Once the client leaves an application or commit for a joined group
  for a replay, it leaves every later envelope for that group too
  (`Failed { retryable: true }`) until the held one is processed or given
  up. Before, a later envelope was processed against the epoch before the
  held commit, failed, and was acknowledged (`Failed` or `RejoinNeeded`),
  and lost. The hold is kept in memory; a restart starts without it, as
  the operator replays from the oldest unacknowledged envelope.

## v0.6.1 — 2026-10-31

### Breaking

- Nothing.

### Added

- `airdress_mls::engine::WELCOME_KEY_PACKAGE_NOT_FOUND`: the exact error
  `MlsEngine::process_welcome` gives when a Welcome names a key package
  the engine does not hold.

### Changed

- **`Client::process` asks to rejoin when a Welcome names a key package
  this device does not hold**, in a conversation it has no group in: the
  event is `RejoinNeeded` (acknowledged) instead of `Failed { retryable:
  false }`, so a host posts its rejoin request instead of losing the
  conversation for good. A Welcome for a conversation the device already
  holds, or one that fails for any other reason, is still `Failed`.

## v0.6.0 — 2026-10-29

### Breaking

- **`LanePayload` and `Message` gain two public fields**, `r#ref:
  Option<String>` and `reply_to: Option<ReplyTo>`. A consumer that builds
  either with a struct literal adds them (`None` for both keeps today's
  meaning); one that only reads them changes nothing.
- The provider upgrade changes nothing in the C ABI or the wire. A
  consumer that also names `mls-rs` or `mls-rs-core` itself must move them
  with this pin, to 0.57 and 0.27. Moving the pin also needs `mls-rs-codec` 0.7.1 in the
  consumer's lockfile (`cargo update -p mls-rs-codec`): mls-rs 0.57 asks
  for `^0.7` but calls a function 0.7.1 added, so a lockfile still on
  0.7.0 does not build.

### Added

- **A message can carry its own reference, and a reply what it answers**
  (SPEC-174 174-A.1). The lane payload's object form now reads
  `{"blocks": [...], "ref": "...", "reply_to": {...}}`, and the two keys
  reach the receiver's `Message`. `ReplyTo` holds `ref` (absent for a
  quote-only reply to an old client's message), `from`, `by_session`,
  `kind` and `snippet`, and serializes exactly as it travels, with absent
  keys absent rather than `null`. A malformed `ref` or `reply_to` is read
  as absent and never refuses the message; unknown keys stay ignored, at
  the top level and inside `reply_to`. The C ABI is unchanged: the phone
  decodes payloads in Dart.
- `LanePayload::encode_message(blocks, ref, reply_to)`, the object form a
  current device sends, and `mint_message_ref()`, sixteen random bytes as
  base64url without padding. `encode_device` still sends the bare array.
- Six lane payload vectors (174-A.2): `object-with-ref`, `reply-with-ref`,
  `quote-only-reply`, `unknown-keys-ignored`,
  `malformed-reply-to-is-no-reply` and `ref-not-a-string-is-no-ref`.
- A fuzz target for `LanePayload::decode`, and its pure tests under Miri.

### Fixed

- **RUSTSEC-2026-0387 (crypto-bigint 0.5: secret-dependent branches in
  code meant to be constant time) is out of the tree.** It came in
  through `mls-rs-crypto-rustcrypto` 0.21, whose P-256 and P-384 are not
  optional. Moving to `mls-rs-crypto-rustcrypto` 0.23, `mls-rs` 0.57 and
  `mls-rs-core` 0.27 brings p256/p384 0.14 and crypto-bigint 0.7.10.
  Nothing here ever ran a secret through it (only `CURVE25519_CHACHA` is
  configured), but the library is linked into apps and a CLI that run
  `cargo deny`. Groups, Welcomes, commits, application messages and the
  sealed state on disk are read both ways between this build and v0.5.0
  (a cross-build run of all four, in both directions), and a Welcome
  costs the same 854 bytes a leaf, so `GROUP_LEAF_CAP` stands. The
  stricter decode in mls-rs 0.57 refuses a message with trailing bytes,
  which no airdress-mls build has ever sent.

### Changed

- The MLS provider now brings its own ChaCha20 (0.10, beside the sealed
  stores' 0.9). The workspace turns on its `zeroize` feature, which the
  provider leaves off, so MLS message ciphers still wipe their keystream
  state on drop; CI checks the feature on every chacha20 in the graph.

## v0.5.0 — 2026-10-24

### Breaking

- **A committing device refuses a group conversation past 137 leaves**
  (`group_context::GROUP_LEAF_CAP`), as it already refused one past 32
  persons, with the same `GroupRule::TooManyPersons` ("that would make the
  group too big"). Only the sending side holds it; a receiver applies a
  bigger commit. 137 is what fits the operator's Welcome limit
  (`chat.limits.max_welcome_bytes`, default 147 456 — its own limit by the
  owner's ruling of 2026-10-09) with 20 % headroom: measured at 854 bytes
  a leaf plus 640 fixed (SPEC-145 145-G1.14, `tests/welcome_size.rs`, run
  with `--ignored`). 32 persons with 4 devices each (~110 KB) fit.

### Added

- `group_context::GROUP_LEAF_CAP` and the measurement that sets it.
- **A decrypt can say which leaf sent the message.**
  `MlsEngine::decrypt_with_sender` returns a `DecryptedMessage`: the
  plaintext and the sending `GroupMember` (index, identity, airdress), by
  the `sender_index` MLS authenticated. `decrypt` is unchanged and now
  delegates to it. Across the C ABI it is the new export
  `airdress_mls_decrypt_bound_with_sender`: a list of exactly three items
  (plaintext, the leaf's identity as `airdress_mls_group_members` gives
  it, the leaf index as four bytes little-endian), freed with
  `airdress_mls_free_bytes_list`. It lets the phone hold an agent session's
  signature to the leaf that sent the message (SPEC-166 166-G.4).

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
