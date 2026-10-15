#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Reports the workspace's `unsafe` surface from the source (issue #11,
# tracking the `unsafe` count without a new tool). For each crate it lists
# whether the workspace's `unsafe_code = "forbid"` applies, and counts in
# its `src` tree the `unsafe` blocks, functions, impls and traits, and the
# `SAFETY:` comments. The counts come from text matching and are
# approximate (for example, an `unsafe` inside a string or a doc comment is
# not excluded); they track change over time, they are not a proof. The
# report never fails: it gates nothing.
#
# Usage: scripts/unsafe-report.sh [markdown output file]
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
out="${1:-/dev/stdout}"
cd "$root"

count() {
    # Lines in Rust sources under $1 matching the extended regex $2,
    # ignoring line comments.
    grep -rhE --include='*.rs' "$2" "$1" 2>/dev/null | grep -vcE '^[[:space:]]*//' || true
}

{
    printf '# `unsafe` surface\n\n'
    printf 'Commit `%s`. Text counts over `crates/*/src`, approximate.\n\n' \
        "$(git rev-parse --short HEAD)"
    printf '| Crate | `unsafe_code` | Blocks | Functions | Impls | Traits | `SAFETY:` comments |\n'
    printf '| --- | --- | ---: | ---: | ---: | ---: | ---: |\n'
    total_blocks=0
    for manifest in crates/*/Cargo.toml; do
        dir="$(dirname "$manifest")"
        crate="$(basename "$dir")"
        if grep -qE '^[[:space:]]*workspace[[:space:]]*=[[:space:]]*true' \
            <(sed -n '/^\[lints\]/,/^\[/p' "$manifest"); then
            policy='forbid (workspace)'
        else
            policy='allowed (own lint set)'
        fi
        blocks=$(count "$dir/src" 'unsafe[[:space:]]*\{')
        functions=$(count "$dir/src" 'unsafe[[:space:]]+(extern[[:space:]]+"[^"]*"[[:space:]]+)?fn[[:space:]]')
        impls=$(count "$dir/src" 'unsafe[[:space:]]+impl[[:space:]<]')
        traits=$(count "$dir/src" 'unsafe[[:space:]]+trait[[:space:]]')
        safety=$(grep -rhcE --include='*.rs' '//[[:space:]]*SAFETY:' "$dir/src" 2>/dev/null \
            | awk '{ s += $1 } END { print s + 0 }' || true)
        total_blocks=$((total_blocks + blocks))
        printf '| `%s` | %s | %s | %s | %s | %s | %s |\n' \
            "$crate" "$policy" "$blocks" "$functions" "$impls" "$traits" "$safety"
    done
    printf '\nTotal `unsafe` blocks: %s.\n' "$total_blocks"
} > "$out"
