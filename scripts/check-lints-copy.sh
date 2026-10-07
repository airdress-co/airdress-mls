#!/usr/bin/env bash
# The FFI crate's lint block is the workspace's, with one line changed.
#
# Cargo cannot inherit `[workspace.lints]` and override a single lint, so
# `crates/airdress-mls-ffi/Cargo.toml` carries a copy with `unsafe_code`
# lowered from "forbid" to "deny" (rust guide R-UNS-1). This fails when
# the copy and the original drift apart in anything but that line.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

lints() {
    sed -n '/^\[\(workspace\.\)\{0,1\}lints\.rust\]/,$p' "$1" \
        | sed 's/^\[workspace\.lints\./[lints./' \
        | grep -v '^unsafe_code' \
        | sed 's/[[:space:]]*#.*$//' \
        | grep -v '^[[:space:]]*$'
}

if ! diff -u --label workspace --label ffi <(lints Cargo.toml) <(lints crates/airdress-mls-ffi/Cargo.toml); then
    echo "check-lints-copy: the FFI crate's lints differ from [workspace.lints]" >&2
    exit 1
fi
grep -q '^unsafe_code = "forbid"' Cargo.toml || { echo "check-lints-copy: the workspace must forbid unsafe_code" >&2; exit 1; }
grep -q '^unsafe_code = "deny"' crates/airdress-mls-ffi/Cargo.toml || { echo "check-lints-copy: the FFI crate must deny unsafe_code" >&2; exit 1; }
echo "check-lints-copy: the FFI crate's lints match the workspace's"
