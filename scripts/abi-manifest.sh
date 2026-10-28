#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Prints the ABI manifest of libkaryos's header (karyos#700): the ABI
# version, the target triple, and for every public struct its size, its
# alignment and each field's offset, then every integer constant the header
# defines. A binding asserts its own declarations against it.
#
# It is measured, not parsed: a probe generated from the header's
# one-field-per-line structs is compiled with the host C compiler (`cc`,
# or $CC) against the header and run. So the manifest is the target's
# own layout; LP64 Linux and macOS are expected to print the same file
# apart from `target`, and a difference is committed as one file per
# triple (abi/<triple>.txt).
#
# Usage: scripts/abi-manifest.sh [HEADER] (default the karyos-ffi header).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
header="${1:-$root/crates/karyos-ffi/include/karyos.h}"
cc="${CC:-cc}"

fail() {
    printf '%s\n' "abi-manifest: $*" >&2
    exit 1
}

[ -f "$header" ] || fail "no header $header"
triple="$(rustc -vV | sed -n 's/^host: //p')"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
probe="$work/probe.c"

# The structs: `typedef struct NAME {` to `} NAME;`, one field per line
# (`TYPE NAME;`, `TYPE *NAME;` or `TYPE NAME[N];`), comments skipped.
awk '
    /^typedef struct karyos_[a-z0-9_]+ \{$/ { name = $3; fields = ""; inside = 1; next }
    inside && /^\} karyos_[a-z0-9_]+;$/ { print name fields; inside = 0; next }
    inside {
        line = $0
        sub(/\/\*.*\*\//, "", line)
        if (line ~ /^[[:space:]]*(\/\*|\*)/ || line !~ /;[[:space:]]*$/) next
        sub(/;[[:space:]]*$/, "", line)
        sub(/\[.*\]$/, "", line)
        n = split(line, words, /[[:space:]*]+/)
        field = words[n]
        if (field != "") fields = fields " " field
    }
' "$header" >"$work/structs"
[ -s "$work/structs" ] || fail "no structs in $header"

# The integer constants: `#define KARYOS_NAME VALUE`, with VALUE an
# integer literal or a parenthesised expression; the include guard and
# function-like macros are not constants.
grep -oE '^#define KARYOS_[A-Z0-9_]+ [-(0-9][^/]*' "$header" |
    awk '{print $2}' | grep -v '^KARYOS_H$' >"$work/constants" || true

{
    printf '%s\n' '#include <stdalign.h>'
    printf '%s\n' '#include <stddef.h>'
    printf '%s\n' '#include <stdio.h>'
    printf '%s\n' "#include \"$header\""
    printf '%s\n' 'int main(void) {'
    printf '%s\n' '    printf("abi_version=%d.%d.%d\n", KARYOS_ABI_VERSION_MAJOR, KARYOS_ABI_VERSION_MINOR, KARYOS_ABI_VERSION_PATCH);'
    printf '%s\n' "    printf(\"target=$triple\\n\");"
    while read -r name fields; do
        printf '%s\n' "    printf(\"struct $name size=%zu align=%zu\\n\", sizeof($name), alignof($name));"
        for field in $fields; do
            printf '%s\n' "    printf(\"  $field offset=%zu size=%zu\\n\", offsetof($name, $field), sizeof((($name *)0)->$field));"
        done
    done <"$work/structs"
    while read -r constant; do
        printf '%s\n' "    printf(\"const $constant=%lld\\n\", (long long)($constant));"
    done <"$work/constants"
    printf '%s\n' '    return 0;'
    printf '%s\n' '}'
} >"$probe"

"$cc" -std=c11 -Wall -Werror -o "$work/probe" "$probe" ||
    fail "the probe does not compile against $header"
"$work/probe"
