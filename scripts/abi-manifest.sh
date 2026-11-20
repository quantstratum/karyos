#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Prints the ABI manifest of libkaryos's header (karyos#700): the ABI
# version, the target triple, and for every public struct its size, its
# alignment and each field's offset, every constant the header defines,
# and every other declaration (function prototypes, inline functions'
# signatures, callback and other typedefs) as written, normalised. A
# binding asserts its own declarations against it.
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

# The declarations, from the header without comments, preprocessor lines
# or its C++ guards (the `extern "C"` open and its close), cut into
# statements at the top level (a `;`, or the `}` that ends an inline
# function's body), whitespace collapsed:
#
#   S NAME FIELD...   a `typedef struct NAME { ... } NAME;`, its fields
#   D TEXT            any other declaration (a prototype, a callback or
#                     other typedef), as written, normalised
#
# A struct member that is not one field (`TYPE NAME`, `TYPE *NAME` or
# `TYPE NAME[N]`) or a top-level statement of no known form is an error,
# never skipped.
awk '
    BEGIN { cpp = 0 }
    /^#ifdef (__cplusplus|KARYOS_H_EXTERN_C_OPEN)/ { cpp = 1; next }
    cpp && /^#endif/ { cpp = 0; next }
    cpp { next }
    { text = text $0 "\n" }
    END {
        # Comments out, character by character.
        out = ""; i = 1; n = length(text)
        while (i <= n) {
            two = substr(text, i, 2)
            if (two == "/*") {
                j = index(substr(text, i + 2), "*/")
                if (j == 0) { print "E unterminated comment"; exit }
                i += j + 3; out = out " "; continue
            }
            if (two == "//") {
                j = index(substr(text, i), "\n")
                i += (j == 0 ? n : j - 1); continue
            }
            out = out substr(text, i, 1); i++
        }
        m = split(out, lines, "\n"); body = ""
        for (k = 1; k <= m; k++) if (lines[k] !~ /^[[:space:]]*#/) body = body " " lines[k]
        gsub(/[[:space:]]+/, " ", body)
        depth = 0; stmt = ""
        n = length(body)
        for (i = 1; i <= n; i++) {
            c = substr(body, i, 1); stmt = stmt c
            if (c == "{") depth++
            else if (c == "}") {
                depth--
                if (depth == 0 && stmt ~ /^ *static inline /) { emit(stmt); stmt = "" }
            } else if (c == ";" && depth == 0) { emit(stmt); stmt = "" }
        }
        if (stmt !~ /^ *$/) print "E trailing text: " stmt
    }
    function trim(s) { sub(/^ +/, "", s); sub(/ +$/, "", s); return s }
    function norm(s) {
        s = trim(s)
        gsub(/ *\( */, "(", s); gsub(/ *\) */, ")", s); gsub(/ *, */, ", ", s)
        gsub(/ *\* */, " *", s); gsub(/ *\[ */, "[", s); gsub(/ *\] */, "]", s)
        sub(/ *;$/, "", s)
        return s
    }
    function emit(s,    name, inner, parts, count, k, field, words, w) {
        s = trim(s)
        if (s ~ /^typedef struct karyos_[a-z0-9_]+ \{/) {
            name = s; sub(/^typedef struct /, "", name); sub(/ .*/, "", name)
            if (s !~ ("\\} " name " ?;$")) { print "E struct " name " not closed as " name; return }
            inner = s; sub(/^[^{]*\{/, "", inner); sub(/\}[^}]*$/, "", inner)
            count = split(inner, parts, ";"); line = "S " name
            for (k = 1; k <= count; k++) {
                field = norm(parts[k])
                if (field == "") continue
                if (field !~ /^(const )?[a-z][a-z0-9_]*( \*+| )[a-z][a-z0-9_]*(\[[A-Za-z0-9_]+\])?$/) {
                    print "E struct " name ": member not one field: " field; return
                }
                sub(/\[.*\]$/, "", field)
                w = split(field, words, /[ *]+/)
                line = line " " words[w]
            }
            print line
        } else if (s ~ /^static inline /) {
            sub(/ ?\{.*$/, "", s); print "D " norm(s)
        } else if (s ~ /^typedef / || s ~ /\(/) {
            print "D " norm(s)
        } else {
            print "E not a declaration: " s
        }
    }
' "$header" >"$work/declarations"
if grep '^E ' "$work/declarations" >&2; then
    fail "cannot parse $header"
fi
grep '^S ' "$work/declarations" | cut -c3- >"$work/structs"
[ -s "$work/structs" ] || fail "no structs in $header"

# The constants: every object-like `#define KARYOS_NAME VALUE` but the
# include guard, whatever VALUE is; the probe prints each as an integer,
# so a constant that is not one fails to compile, loudly.
grep -E '^#define KARYOS_[A-Z0-9_]+[[:space:]]+[^[:space:]]' "$header" |
    awk '{print $2}' | grep -v '^KARYOS_H$' >"$work/constants" || true

{
    printf '%s\n' '#include <stdalign.h>'
    printf '%s\n' '#include <stddef.h>'
    printf '%s\n' '#include <stdio.h>'
    printf '%s\n' "#include \"$header\""
    # An integer constant expression, or the probe does not compile.
    while read -r constant; do
        printf '%s\n' "_Static_assert((($constant) % 1) == 0, \"$constant is not an integer constant\");"
    done <"$work/constants"
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
        printf '%s\n' "    if (($constant) < 0) printf(\"const $constant=-%llu\\n\", -(unsigned long long)($constant)); else printf(\"const $constant=%llu\\n\", (unsigned long long)($constant));"
    done <"$work/constants"
    printf '%s\n' '    return 0;'
    printf '%s\n' '}'
} >"$probe"

"$cc" -std=c11 -Wall -Werror -o "$work/probe" "$probe" ||
    fail "the probe does not compile against $header"
"$work/probe"
# The declarations, as written: a prototype or a typedef that changes is
# an ABI change even where no layout does.
grep '^D ' "$work/declarations" | cut -c3- | sed 's/^/decl /'
