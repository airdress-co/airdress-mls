# Contributing

A change should be something somebody can read in a year and understand
why it is there.

## Before a pull request

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --locked
scripts/check-symbols.sh     # the C ABI against its list
prek run --all-files         # the hooks, over everything
```

CI runs the same things, plus `cargo deny check`.

## House rules that are not obvious

- **The C ABI is a promise to phones already in the field.** Adding an
  export means adding it to `crates/airdress-mls-ffi/symbols.txt` in the
  same change; `scripts/check-symbols.sh` fails otherwise. Removing or
  renaming one is a breaking change for every installed app.
- **`serde_json`'s `preserve_order` must never be enabled**, here or in
  a consumer. Canonical delegation bytes rely on sorted keys; the
  feature would change them silently.
- **Vectors are shared.** `vectors/` is read by this crate's tests and
  by every consumer's (through `airdress_mls::vectors`). A vector is
  never edited in place: a changed expectation is a new vector.
- **No telemetry.** No analytics, no crash reporting, no tracing
  exporter, in this repository or any dependency. `deny.toml` lists the
  bans and CI enforces them.
- **A new test file must be named in CI** in the same change, or it is
  a file that never runs.
- **Document numbers belong in comments**, never in an identifier, a
  string, a test name or a file name. `scripts/check-doc-numbers.sh`
  enforces it.
