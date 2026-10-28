#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Checks libkaryos's ABI manifest (scripts/abi-manifest.sh, less its
# `target` line, karyos#700) measured on this host against two records:
#
# - The committed manifest, crates/karyos-ffi/abi/manifest.txt: a layout,
#   constant or declaration that changed fails until the manifest is
#   regenerated and committed with it:
#
#     scripts/abi-manifest.sh | grep -v '^target=' > crates/karyos-ffi/abi/manifest.txt
#
# - The last released manifest, crates/karyos-ffi/abi/released/<abi>.txt
#   (RELEASING.md adds one per release): a manifest that differs from it
#   must carry a higher ABI version, so regenerating the committed manifest
#   never passes an unversioned change (owner item 48). Before the first
#   release there is none, and the check says so.
#
# Run in pre-push on macOS; LP64 Linux is expected to measure the same
# file, which a Linux run of this script confirms.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
abi="$root/crates/karyos-ffi/abi"
committed="$abi/manifest.txt"
measured="$("$root/scripts/abi-manifest.sh" | grep -v '^target=')"
version() { sed -n 's/^abi_version=//p'; }
new="$(echo "$measured" | version)"

if [ "$measured" != "$(cat "$committed")" ]; then
    diff <(cat "$committed") <(echo "$measured") >&2 || true
    echo "check-abi-manifest: the header at ABI $new does not match crates/karyos-ffi/abi/manifest.txt: regenerate and commit it (see this script)" >&2
    exit 1
fi

released=""
if [ -d "$abi/released" ]; then
    released="$(find "$abi/released" -name '*.txt' | sed 's|.*/||; s|\.txt$||' | sort -V | tail -n 1)"
fi
if [ -z "$released" ]; then
    against="no released manifest yet"
elif [ "$measured" = "$(cat "$abi/released/$released.txt")" ]; then
    against="the same as released ABI $released"
elif [ "$(printf '%s\n%s\n' "$released" "$new" | sort -V | tail -n 1)" = "$new" ] &&
    [ "$new" != "$released" ]; then
    against="changed since released ABI $released, at the new ABI $new"
else
    diff <(cat "$abi/released/$released.txt") <(echo "$measured") >&2 || true
    echo "check-abi-manifest: the header changed since released ABI $released without a higher ABI version (owner item 48)" >&2
    exit 1
fi
echo "abi manifest: $new, $(grep -c '^struct' "$committed") structs, $(grep -c '^const' "$committed") constants, $(grep -c '^decl' "$committed") declarations: matches; $against"
