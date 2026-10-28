#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Builds the conformance test kit beside a libkaryos package
# (scripts/package-libkaryos.sh): the driver daemon the suite's
# `archive-replay` scenarios start, and the admission stub its
# `incompatible-driver` scenarios start (conformance/FORMAT.md), from the
# same core commit as the package, so a binding's runner needs no Rust
# toolchain. Not part of the release package, whose contents are owner
# item 44's: a separate directory, DEST-testkit,
#
#   bin/karyosd
#   bin/karyos-admission-stub       (built with karyos-tools' test-hooks)
#   share/karyos-testkit/MANIFEST   (role, commit, the binaries' SHA-256)
#
# The kit refuses a package of another commit or tree state, and builds
# for the host only. It is not rebuilt with its package: a later
# `make libkaryos` at another commit leaves a stale kit beside the new
# package, so a consumer compares the kit MANIFEST's core_commit with the
# package MANIFEST's before using bin/karyosd, and rebuilds the kit when
# they differ. It is Linux only: the scenarios that need it connect
# a cross-process client, which exists on Linux only.
#
# Usage: scripts/package-testkit.sh [PACKAGE] (default target/libkaryos).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cargo="${CARGO:-cargo}"
target_dir="${CARGO_TARGET_DIR:-$root/target}"
package="${1:-$target_dir/libkaryos}"
case "$package" in
/*) ;;
*) package="$PWD/$package" ;;
esac
while [ "$package" != / ] && [ "${package%/}" != "$package" ]; do package="${package%/}"; done
dest="$package-testkit"

fail() {
    echo "package-testkit: $*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "the test kit is Linux only (its scenarios need a cross-process client)"
manifest="$package/share/karyos/MANIFEST"
[ -f "$manifest" ] || fail "no libkaryos package at $package (make libkaryos)"
manifest_value() {
    sed -n "s/^$1=//p" "$manifest"
}
package_commit="$(manifest_value core_commit)"
package_dirty="$(manifest_value core_dirty)"
commit="$(git -C "$root" rev-parse HEAD)"
if [ -n "$(git -C "$root" status --porcelain)" ]; then
    dirty=1
else
    dirty=0
fi
[ "$package_commit" = "$commit" ] ||
    fail "the package is core $package_commit, the tree is $commit: package the library first"
[ "$package_dirty" = "$dirty" ] ||
    fail "the package says core_dirty=$package_dirty, the tree is core_dirty=$dirty"
if [ -e "$dest" ] && [ ! -f "$dest/share/karyos-testkit/MANIFEST" ]; then
    fail "$dest exists and is not a test kit; remove it or pick another PACKAGE"
fi

cd "$root"
"$cargo" build -p karyos-tools --bin karyosd --release --locked
binary="$target_dir/release/karyosd"
[ -x "$binary" ] || fail "cargo built no $binary"
"$binary" --help >/dev/null || fail "$binary --help failed"
# A test-kit binary only: the product karyosd never carries a test path.
"$cargo" build -p karyos-tools --features test-hooks --bin karyos-admission-stub --release --locked
stub="$target_dir/release/karyos-admission-stub"
[ -x "$stub" ] || fail "cargo built no $stub"

stage="$dest.partial.$$"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/bin" "$stage/share/karyos-testkit"
cp "$binary" "$stage/bin/karyosd"
cp "$stub" "$stage/bin/karyos-admission-stub"
sha="$(sha256sum "$stage/bin/karyosd" | cut -d ' ' -f 1)"
stub_sha="$(sha256sum "$stage/bin/karyos-admission-stub" | cut -d ' ' -f 1)"
cat >"$stage/share/karyos-testkit/MANIFEST" <<EOF
role=conformance test kit, not for release
release_package=no
core_commit=$commit
core_dirty=$dirty
karyosd_sha256=$sha
admission_stub_sha256=$stub_sha
target=$(rustc -vV | sed -n 's/^host: //p')
rustc=$(rustc -V)
profile=release
EOF

cat >"$stage/README" <<EOF
The Karyos conformance test kit: karyosd and the admission stub of core
$commit, for a binding's conformance runner. It is not a release package
(owner item 44): never ship or install it; the released karyosd is its
own signed artifact, and libkaryos is released without it.
EOF

rm -rf "$dest"
mv "$stage" "$dest"
echo "test kit (not a release package) for core $commit in $dest: bin/karyosd (sha256 $sha), bin/karyos-admission-stub (sha256 $stub_sha)"
