#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Checks C-LINKAGE's third condition against a libkaryos package
# (scripts/package-libkaryos.sh): two copies of the library in one
# process each refuse the other's handles with KARYOS_E_CLOSED, and keep
# their own usable (karyos.h, Rules). The package's shared library is
# copied to two files, so each loads with its own statics, and
# scripts/check-libkaryos-copies.c loads both with RTLD_LOCAL and checks
# a driver and a client handle in both directions.
#
# It compiles C, so it is a check of its own (`make libkaryos-copies-check`),
# like the static link check, and not part of pre-push.
#
# Usage: scripts/check-libkaryos-copies.sh [PACKAGE] (default
# target/libkaryos).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
package="${1:-${CARGO_TARGET_DIR:-$root/target}/libkaryos}"
cc="${CC:-cc}"

fail() {
    echo "check-libkaryos-copies: $*" >&2
    exit 1
}

[ -f "$package/share/karyos/MANIFEST" ] || fail "no libkaryos package at $package (make libkaryos)"
if [ "$(uname -s)" = Darwin ]; then
    library="$package/lib/libkaryos.dylib"
    suffix=dylib
    libs=()
else
    library="$package/lib/libkaryos.so"
    suffix=so
    libs=(-ldl)
fi
[ -e "$library" ] || fail "$package has no $(basename "$library")"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# Two files, not two links to one: a loader that finds a library already
# loaded from the same file returns that copy.
cp -L "$library" "$work/copy-a.$suffix"
cp -L "$library" "$work/copy-b.$suffix"
"$cc" -std=c11 -Wall -Wextra -Werror -o "$work/copies" \
    -I "$package/include" "$root/scripts/check-libkaryos-copies.c" ${libs[@]+"${libs[@]}"} ||
    fail "the check program did not build"
"$work/copies" "$work/copy-a.$suffix" "$work/copy-b.$suffix" ||
    fail "a copy accepted the other's handle, or refused its own"
