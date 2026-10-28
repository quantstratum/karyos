#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs the conformance suite against a released libkaryos artifact, not a
# build tree (karyos#700): checks the tarball against the SHA256SUMS beside
# it, unpacks it, and runs the reference runner (karyos-ffi's
# tests/conformance.rs) built with `--cfg karyos_package`, so it links the
# package's own libkaryos instead of the crate. The result is printed with
# the artifact's digest, for the release notes' Evidence. The suite and
# its declarations are the tree's, so the tree must be clean and at the
# package's `core_commit`; a failing run prints its result too.
#
# The suite's cross-process scenarios run on Linux only (FORMAT.md); a
# macOS run covers the rest. The scenarios that start karyosd need the
# conformance test kit of the same commit (scripts/package-testkit.sh).
#
# Usage: scripts/conformance-package.sh TARBALL
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cargo="${CARGO:-cargo}"
tarball="${1:?usage: conformance-package.sh TARBALL}"

fail() {
    echo "conformance-package: $*" >&2
    exit 1
}

[ -f "$tarball" ] || fail "no artifact $tarball"
dir="$(cd "$(dirname "$tarball")" && pwd)"
name="$(basename "$tarball")"
[ -f "$dir/SHA256SUMS" ] || fail "no SHA256SUMS beside $tarball"
if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum "$tarball" | cut -d ' ' -f 1)"
else
    digest="$(shasum -a 256 "$tarball" | cut -d ' ' -f 1)"
fi
grep -qx "$digest  $name" "$dir/SHA256SUMS" ||
    fail "$name does not match SHA256SUMS"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tar -xzf "$tarball" -C "$work"
package="$(find "$work" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
[ -f "$package/share/karyos/MANIFEST" ] || fail "$name is not a libkaryos package"
grep -qx 'contents=library' "$package/share/karyos/MANIFEST" ||
    fail "$name's MANIFEST does not say contents=library"

# The suite and the declarations it asserts (tests/support/abi.rs) are
# the tree's, so they must be the package's: a clean tree at the commit
# the package was built from.
core="$(sed -n 's/^core_commit=//p' "$package/share/karyos/MANIFEST")"
[ -z "$(git -C "$root" status --porcelain)" ] ||
    fail "the tree has uncommitted changes; the suite must be the package's commit's"
[ "$core" = "$(git -C "$root" rev-parse HEAD)" ] ||
    fail "$name was built from $core, not HEAD $(git -C "$root" rev-parse HEAD); check that commit out"

# Its own target directory: a cfg change rebuilds the test, never the
# tree's ordinary build.
target="${CARGO_TARGET_DIR:-$root/target}/conformance-package"
lib="$package/lib"
# A failing run still prints its evidence line: no `set -e` around it.
set +e
RUSTFLAGS="${RUSTFLAGS:-} --cfg karyos_package -L native=$lib" \
    CARGO_TARGET_DIR="$target" LD_LIBRARY_PATH="$lib" DYLD_LIBRARY_PATH="$lib" \
    "$cargo" test -p karyos-ffi --test conformance --locked 2>&1 | tee "$work/log"
status="${PIPESTATUS[0]}"
set -e
result="$(grep -E '^test result' "$work/log" | tail -n 1)"
echo "conformance against $name (sha256 $digest), ABI $(sed -n 's/^abi_version=//p' "$package/share/karyos/MANIFEST"), core $core: ${result:-no result} (exit $status)"
exit "$status"
