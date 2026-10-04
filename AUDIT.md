# What was checked before this repository was made public

Done 2026-10-04, when the crate was extracted from airdress-operator
with `git filter-repo --path crates/airdress-mls-ffi/ --path
<the delegation vectors>`: 222 commits, every one authored inside a
private repository. Publishing a repository publishes its history, so
every check below ran over all of it, not the tip.

## 1. Is there a secret in it?

| Tool | Scope | Result |
| ---- | ----- | ------ |
| gitleaks 8.30.1 | `git --log-opts=--all`, 188 commits with content | no leaks found |
| trufflehog 3.97.9 | `git file://…`, every commit | 0 verified, 0 unverified |

The only key material in the tree is test material by construction:
the delegation vectors carry deterministic seeds (`[1; 32]`, `[2; 32]`,
…) whose whole purpose is to be reproduced, and every other test
derives its keys in-process.

## 2. Does anything here name our estate?

`scripts/check-public.sh --history` greps every blob in every reachable
commit for the GCP project, the state bucket, the QA airdress, fleet
host names and addresses, the jump host, private and tailnet address
ranges, internal hosts and Secret Manager names. **Clean.** A wider
manual pass over the same blobs for `airdr.es`, cloud and hosting
providers, mail addresses and any IPv4 literal found nothing either.
The crate is a protocol engine: it is handed a seed and a directory and
never had a reason to name a host. The airdresses in its tests are
`alice.test.airdress.co`-style fixtures.

**Commit messages are not blobs**, and that scan does not read them.
Read separately (`git log --format=%B`), two messages inherited from
the operator's release train named internal things: one a fleet host
name, one the QA airdress's name. Neither was a credential or an
address. On the owner's decision (2026-10-04) both messages were
rewritten with `git filter-repo --replace-message` before anything was
pushed, so no published clone ever carried them; the same grep over
every message afterwards finds nothing. A third message says "VM3",
which is a label, not an address, and stays.

## 3. Document numbers

`scripts/check-doc-numbers.sh` passes over the tree. The one string
literal carrying a number is the MLS sender-binding AAD label,
`airdress-spec-061-v2`: those bytes are inside every application
message's authenticated data, so renaming it breaks every conversation
in the field. It carries an explicit `allow-doc-number:` marker saying
so. No identifier, file name or test name carries one.

## 4. Can it build with no credential?

Yes. Every dependency is on crates.io (`deny.toml` refuses any git
source), so `cargo test` works in a fresh clone with no token.

## What the extraction changed, and why each

| Was | Is | Why |
| --- | --- | --- |
| one crate, `airdress-mls-ffi` | `airdress-mls` (engine) + `airdress-mls-ffi` (C ABI) | Rust consumers link the engine without a `cdylib` and its unsafe boundary |
| `license.workspace` → `LicenseRef-Proprietary` | `Apache-2.0` | relicensed by the copyright holder; the marker was inherited from the operator's workspace |
| version `0.1.116` | `0.2.0` | that number tracked the operator's release train |
| vectors at `airdress-common/tests/fixtures/` | `vectors/`, compiled in as `airdress_mls::vectors` | one vector set, read by every consumer |
| `test_support` crate-private | `test-support` feature | the FFI crate's tests are now another crate's |
| yanked `fastrand 2.4.0`, `spin 0.10.0` in the lockfile | `2.5.0`, `0.10.1` | `cargo deny` refuses yanked crates; both were inherited |

The C ABI is unchanged: the built library exports exactly the 33 names
in `crates/airdress-mls-ffi/symbols.txt`, and nothing else, which
`scripts/check-symbols.sh` asserts on every CI run.

## What this audit does not claim

That the MLS usage is correct. It says nothing was leaked and the thing
builds in the open. `SECURITY.md` says what a defect would look like.
