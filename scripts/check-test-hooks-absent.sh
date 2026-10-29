#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The conformance test kit's fault hook (karyos-ffi feature `test-hooks`,
# include/karyos_test_hooks.h; karyos#699) is absent from the release
# library: neither its shared nor its static libkaryos exports a
# `karyos_test_` symbol, and neither carries the hook's panic text, so the
# code is not there either, not only the symbol. Run after a release
# build (`make build-release`, which pre-push runs first).
#
# Usage: scripts/check-test-hooks-absent.sh [RELEASE DIR] (default
# target/release).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
release="${1:-${CARGO_TARGET_DIR:-$root/target}/release}"
# The panic payload of the hook in crates/karyos-ffi/src/api/driver.rs.
marker="the fault hook's panic"

fail() {
    echo "check-test-hooks-absent: $*" >&2
    exit 1
}

grep -qF "\"$marker\"" "$root/crates/karyos-ffi/src/api/driver.rs" ||
    fail "the hook's panic text is no longer \"$marker\": update this check"
checked=0
for library in "$release/libkaryos_ffi.so" "$release/libkaryos_ffi.dylib" "$release/libkaryos_ffi.a"; do
    [ -f "$library" ] || continue
    checked=$((checked + 1))
    if nm -g "$library" 2>/dev/null | grep -q 'karyos_test_'; then
        fail "$library exports a karyos_test_ symbol"
    fi
    if LC_ALL=C grep -aqF "$marker" "$library"; then
        fail "$library carries the fault hook's code"
    fi
done
[ "$checked" -ge 2 ] || fail "no shared and static libkaryos_ffi in $release (make build-release)"
echo "check-test-hooks-absent: $checked libraries, no fault hook"
