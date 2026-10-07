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

## v0.3.0 — unreleased

Everything since `5cf9036` (0.2.0, the revision the operator pins).

### Breaking

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
