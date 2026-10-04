#!/usr/bin/env bash
# The C ABI, held to its list.
#
# Builds the FFI crate's shared library in release mode and compares the
# names it exports with `crates/airdress-mls-ffi/symbols.txt`, in both
# directions. Also refuses any exported name outside the `airdress_mls_`
# prefix: the library is loaded into somebody else's process, and a stray
# export is a name collision waiting for the next dependency bump.
#
# Usage: scripts/check-symbols.sh [path/to/libairdress_mls_ffi.so]
#   With a path, checks that file instead of building one.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

LIST=crates/airdress-mls-ffi/symbols.txt
LIB="${1:-}"
if [[ -z "$LIB" ]]; then
    cargo build --locked --release -p airdress-mls-ffi
    LIB=target/release/libairdress_mls_ffi.so
fi
[[ -s "$LIB" ]] || { echo "check-symbols: no library at $LIB" >&2; exit 1; }

NM="${NM:-nm}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

grep -vE '^[[:space:]]*(#|$)' "$LIST" | sort > "$tmp/listed"
if [[ -n "$(uniq -d "$tmp/listed")" ]]; then
    echo "check-symbols: $LIST names a symbol twice:" >&2
    uniq -d "$tmp/listed" >&2
    exit 1
fi

# Defined, dynamic, code (T) or data (D/B/R) symbols.
"$NM" -D --defined-only "$LIB" | awk '$2 ~ /^[TDBR]$/ {print $3}' | sort -u > "$tmp/exported"

fail=0
if stray=$(grep -v '^airdress_mls_' "$tmp/exported"); then
    echo "check-symbols: exports outside the airdress_mls_ prefix:" >&2
    echo "$stray" >&2
    fail=1
fi
if ! diff -u --label "$LIST" --label "$LIB" "$tmp/listed" "$tmp/exported"; then
    echo "check-symbols: the library's exports and $LIST disagree (- listed only, + exported only)" >&2
    fail=1
fi
[[ $fail -eq 0 ]] || exit 1
echo "check-symbols: $(wc -l < "$tmp/exported") exports, identical to $LIST"
