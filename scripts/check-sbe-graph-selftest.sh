#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Negative controls of check-sbe-graph.py (karyos#631): in a throwaway
# workspace of path crates named as the real ones (nothing is downloaded),
# the check must fail, naming the breach, when a crate other than
# karyos-sbe depends on an IronSBE crate, when an excluded IronSBE crate
# is in the graph, and when karyos-feed depends on karyos-sbe (directly or
# through another crate); and it must pass silently on the clean layout.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cargo="${CARGO:-cargo}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

crate() {
    # crate DIR NAME DEPENDENCIES
    mkdir -p "$1/src"
    printf '[package]\nname = "%s"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n[dependencies]\n%s\n' \
        "$2" "$3" >"$1/Cargo.toml"
    : >"$1/src/lib.rs"
}

# make_workspace FEED_DEPS SBE_DEPS OTHER_DEPS MIDDLE_DEPS
make_workspace() {
    rm -rf "$work/ws" "$work/vendor"
    local name
    for name in ironsbe-core ironsbe-transport; do
        crate "$work/vendor/$name" "$name" ""
    done
    mkdir -p "$work/ws"
    printf '[workspace]\nmembers = ["karyos-feed", "karyos-sbe", "karyos-other", "karyos-middle"]\nresolver = "2"\n' \
        >"$work/ws/Cargo.toml"
    crate "$work/ws/karyos-feed" karyos-feed "$1"
    crate "$work/ws/karyos-sbe" karyos-sbe "$2"
    crate "$work/ws/karyos-other" karyos-other "$3"
    crate "$work/ws/karyos-middle" karyos-middle "$4"
    "$cargo" generate-lockfile --offline --manifest-path "$work/ws/Cargo.toml" >/dev/null 2>&1
}

failures=0
# expect LABEL WANTED_LINE...: the check fails with exactly these lines, or
# passes silently when none is given.
expect() {
    local label="$1"
    shift
    : >"$work/wanted"
    local line
    for line in "$@"; do
        printf 'check-sbe-graph: %s\n' "$line" >>"$work/wanted"
    done
    local rc=0 code=0
    CARGO="$cargo" python3 "$here/check-sbe-graph.py" --manifest-path "$work/ws/Cargo.toml" \
        >"$work/got" 2>&1 || rc=$?
    if [ -s "$work/wanted" ]; then code=1; fi
    if [ "$rc" -eq "$code" ] && cmp -s "$work/wanted" "$work/got"; then
        return
    fi
    failures=1
    echo "check-sbe-graph-selftest: $label: expected (exit $code):" >&2
    cat "$work/wanted" >&2
    echo "got (exit $rc):" >&2
    cat "$work/got" >&2
}

feed='karyos-feed = { path = "../karyos-feed" }'
sbe='karyos-sbe = { path = "../karyos-sbe" }'
middle='karyos-middle = { path = "../karyos-middle" }'
core='ironsbe-core = { path = "../../vendor/ironsbe-core" }'
transport='ironsbe-transport = { path = "../../vendor/ironsbe-transport" }'

make_workspace "" "$feed
$core" "" ""
expect "clean layout"

make_workspace "" "$feed" "$core" ""
expect "another crate takes an IronSBE crate" \
    "karyos-other depends directly on ironsbe-core: IronSBE enters only through karyos-sbe"

make_workspace "" "$feed
$transport" "" ""
expect "an excluded IronSBE crate in the graph" \
    "ironsbe-transport is in the graph: the record excludes it from the core"

make_workspace "$sbe" "" "" ""
expect "karyos-feed depends on karyos-sbe" \
    "karyos-feed depends on karyos-sbe: the dependency runs the other way"

make_workspace "$middle" "" "" "$sbe"
expect "karyos-feed reaches karyos-sbe through another crate" \
    "karyos-feed depends on karyos-sbe: the dependency runs the other way"

if [ "$failures" -ne 0 ]; then
    exit 1
fi
echo "check-sbe-graph-selftest: every negative control caught, the clean layout passes"
