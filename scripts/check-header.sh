#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Regenerates libkaryos's C header from karyos-ffi's Rust source with
# cbindgen and crates/karyos-ffi/cbindgen.toml (karyos#697, F8 of
# quantstratum-docs: karyos/design/ffi-gap-analysis.md), and fails on any
# difference from the committed crates/karyos-ffi/include/karyos.h,
# trailer included. --write replaces the committed header instead.
#
# cbindgen is a maintainer tool, never a dependency of any crate
# (quantstratum-docs: karyos/reviews/dependency-admission-cbindgen.md):
# it must be installed at exactly the version below,
#   cargo install cbindgen --version 0.29.4 --locked
# or at $CBINDGEN. Another version is refused, so a different generator
# cannot pass a stale header.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
want="cbindgen 0.29.4"
cbindgen="${CBINDGEN:-cbindgen}"
crate="$root/crates/karyos-ffi"
header="$crate/include/karyos.h"

fail() {
    echo "check-header: $*" >&2
    exit 1
}

# Resolved to an absolute path before any directory change, so the binary
# run is the one checked here, whatever directory $CBINDGEN is relative to.
cbindgen="$(command -v "$cbindgen" 2>/dev/null)" ||
    fail "no ${CBINDGEN:-cbindgen}; install it: cargo install cbindgen --version 0.29.4 --locked"
case "$cbindgen" in
/*) ;;
*) cbindgen="$PWD/$cbindgen" ;;
esac
have="$("$cbindgen" --version)"
[ "$have" = "$want" ] || fail "$have found, $want required"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# cbindgen would run `cargo metadata` itself, without --locked or
# --offline, which may fetch or update Cargo.lock: the gate stays offline
# and locked by giving it metadata resolved that way.
cargo metadata --locked --offline --all-features --format-version 1 \
    --manifest-path "$crate/Cargo.toml" >"$work/metadata.json" ||
    fail "cargo metadata --locked --offline failed"
(cd "$crate" && "$cbindgen" --quiet --config cbindgen.toml --crate karyos-ffi \
    --metadata "$work/metadata.json" --output "$work/karyos.h" .)

if [ "${1:-}" = --write ]; then
    cp "$work/karyos.h" "$header"
    echo "check-header: wrote $header"
    exit 0
fi
if ! diff -u "$header" "$work/karyos.h"; then
    fail "include/karyos.h differs from what cbindgen generates; run make header and commit it"
fi
echo "check-header: include/karyos.h is what cbindgen generates"
