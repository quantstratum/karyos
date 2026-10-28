#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Checks the committed ABI manifest, crates/karyos-ffi/abi/manifest.txt,
# against the header measured on this host (scripts/abi-manifest.sh, less
# its `target` line, karyos#700). A layout or constant that changed with
# the same ABI version fails as an unversioned ABI change; one that
# changed with a new ABI version fails until the manifest is regenerated
# and committed with it:
#
#   scripts/abi-manifest.sh | grep -v '^target=' > crates/karyos-ffi/abi/manifest.txt
#
# Run in pre-push on macOS; LP64 Linux is expected to measure the same
# file, which a Linux run of this script confirms.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
committed="$root/crates/karyos-ffi/abi/manifest.txt"
measured="$("$root/scripts/abi-manifest.sh" | grep -v '^target=')"
if [ "$measured" = "$(cat "$committed")" ]; then
    echo "abi manifest: $(sed -n 's/^abi_version=//p' "$committed"), $(grep -c '^struct' "$committed") structs, $(grep -c '^const' "$committed") constants: matches"
    exit 0
fi
diff <(cat "$committed") <(echo "$measured") >&2 || true
old="$(sed -n 's/^abi_version=//p' "$committed")"
new="$(echo "$measured" | sed -n 's/^abi_version=//p')"
if [ "$old" = "$new" ]; then
    echo "check-abi-manifest: the header's layout or constants changed at ABI $new without a new ABI version (owner item 48)" >&2
else
    echo "check-abi-manifest: ABI $old -> $new: regenerate crates/karyos-ffi/abi/manifest.txt and commit it (see this script)" >&2
fi
exit 1
