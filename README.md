# airdress-mls

The MLS ([RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)) client
every airdress device runs, over [`mls-rs`](https://github.com/awslabs/mls-rs).

One implementation for every consumer: the phone app reaches it through
a C ABI, and the operator and the `airdress` CLI link it as a Rust
library. Two copies of the canonical encoding, the credential checks or
the message binding are how a message decrypts in one place and not the
other.

| Path | What |
| ---- | ---- |
| `crates/airdress-mls` | The engine: delegation-carrying credentials, sealed storage, AAD binding, group rules, two-phase commits |
| `crates/airdress-mls-ffi` | The C ABI over it (`cdylib` + `staticlib`) and `symbols.txt`, the exported set |
| `vectors/` | Test vectors every consumer reads, through `airdress_mls::vectors` |

Ciphersuite: CS3, `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`.

## Using it

Consumers pin a revision:

```toml
airdress-mls = { git = "https://github.com/airdress-co/airdress-mls", rev = "<commit>" }
```

The native library for a phone:

```sh
crates/airdress-mls-ffi/build-native.sh android   # or ios, linux, all
```

## Checks

```sh
cargo test --workspace --locked
scripts/check-symbols.sh   # nm over the built library, against symbols.txt
```

## Licence

Apache-2.0. See `LICENSE`, `NOTICE` and `THIRD-PARTY.md`.
