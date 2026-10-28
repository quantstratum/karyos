#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Builds the release artifacts of libkaryos and karyosd for the host, as
# two separate artifacts (owner item 44; karyos#700), into DEST:
#
#   libkaryos-<abi>-<core>-<triple>.tar.gz   the package of
#                                            scripts/package-libkaryos.sh:
#                                            the library alone
#   karyosd-<core>-<triple>.tar.gz           the driver daemon, its own
#                                            artifact
#   SHA256SUMS                               both artifacts' digests
#
# The tree must be clean (KARYOS_PACKAGE_REQUIRE_CLEAN=1): an artifact is
# built from a commit, never from local changes. The conformance test kit
# (scripts/package-testkit.sh) is never put here: it is not a release
# package. Signing is a separate step, scripts/sign-release.sh, run by the
# release key's custodian; this script signs nothing.
#
# The archives are deterministic for a commit and a toolchain: sorted
# entries, owner 0, file times set to the commit's time, and gzip without
# a name or time. Whether two independent builds give the same bytes is
# karyos-deploy's reproducibility gate (C-REPRO), not checked here.
#
# Usage: scripts/release-libkaryos.sh [DEST] (default target/release-artifacts).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cargo="${CARGO:-cargo}"
target_dir="${CARGO_TARGET_DIR:-$root/target}"
dest="${1:-$target_dir/release-artifacts}"
case "$dest" in
/*) ;;
*) dest="$PWD/$dest" ;;
esac

fail() {
    echo "release-libkaryos: $*" >&2
    exit 1
}

[ -z "$(git -C "$root" status --porcelain)" ] ||
    fail "the tree has uncommitted changes; a release artifact is built from a commit"
if [ -e "$dest" ] && [ ! -f "$dest/SHA256SUMS" ]; then
    fail "$dest exists and is not a release directory; remove it or pick another DEST"
fi
commit="$(git -C "$root" rev-parse HEAD)"
epoch="$(git -C "$root" log -1 --format=%ct HEAD)"
triple="$(rustc -vV | sed -n 's/^host: //p')"
core="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$root/Cargo.toml" | head -n 1)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The library package, built clean and checked by its own script.
KARYOS_PACKAGE_REQUIRE_CLEAN=1 CARGO="$cargo" \
    "$root/scripts/package-libkaryos.sh" "$work/package"
abi="$(sed -n 's/^abi_version=//p' "$work/package/share/karyos/MANIFEST")"
[ -n "$abi" ] || fail "the package's MANIFEST has no abi_version"
grep -qx 'contents=library' "$work/package/share/karyos/MANIFEST" ||
    fail "the package's MANIFEST does not say contents=library"
lib_name="libkaryos-$abi-$core-$triple"

# karyosd alone, from the same commit.
"$cargo" build -p karyos-tools --bin karyosd --release --locked
daemon_name="karyosd-$core-$triple"
mkdir -p "$work/$daemon_name/bin"
cp "$target_dir/release/karyosd" "$work/$daemon_name/bin/karyosd"
cp "$root/LICENSE.md" "$work/$daemon_name/LICENSE.md"
cat >"$work/$daemon_name/MANIFEST" <<EOF
artifact=karyosd
core_version=$core
core_commit=$commit
target=$triple
rustc=$(rustc -V)
profile=release
contents=karyosd
excludes=libkaryos
EOF

# `sha256sum`'s output for the files given (GNU coreutils, or shasum).
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$@"
    else
        shasum -a 256 "$@"
    fi
}

# A deterministic gzip'd tar of directory $2 named $1, with GNU tar or
# bsdtar (their owner and time options differ).
archive() {
    local name="$1" dir="$2"
    find "$dir" -exec touch -h -d "@$epoch" {} + 2>/dev/null ||
        find "$dir" -exec touch -h -t "$(date -u -r "$epoch" +%Y%m%d%H%M.%S)" {} +
    (
        cd "$(dirname "$dir")"
        find "$(basename "$dir")" -print | LC_ALL=C sort >"$work/$name.list"
        if tar --version 2>/dev/null | grep -q 'GNU tar'; then
            tar --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
                --no-recursion -cf - -T "$work/$name.list"
        else
            COPYFILE_DISABLE=1 tar --uid 0 --gid 0 --uname '' --gname '' \
                --no-recursion -cf - -T "$work/$name.list"
        fi
    ) | gzip -n -9 >"$work/out/$name.tar.gz"
}

mv "$work/package" "$work/$lib_name"
mkdir -p "$work/out"
archive "$lib_name" "$work/$lib_name"
archive "$daemon_name" "$work/$daemon_name"
(
    cd "$work/out"
    sha256 "$lib_name.tar.gz" "$daemon_name.tar.gz" >SHA256SUMS
)

# Neither artifact holds the other.
tar -tzf "$work/out/$lib_name.tar.gz" | grep -q 'karyosd' &&
    fail "the libkaryos artifact holds karyosd"
tar -tzf "$work/out/$daemon_name.tar.gz" | grep -q 'libkaryos' &&
    fail "the karyosd artifact holds libkaryos"

rm -rf "$dest"
mv "$work/out" "$dest"
echo "release artifacts of core $commit in $dest:"
cat "$dest/SHA256SUMS"
