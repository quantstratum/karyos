#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Negative controls of check-shipped-graph.sh (karyos#953 review): in a
# throwaway workspace whose shipped crate depends on a local crate named
# `tokio`, the check must fail when that dependency is a plain one, and
# also when it is optional behind a nondefault feature; and it must pass
# when the shipped crate does not depend on it. Path crates only, so
# nothing is downloaded.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cargo="${CARGO:-cargo}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

make_workspace() {
    local shipped="$1" features="$2" admitted="${3:-}"
    rm -rf "$work/ws" "$work/vendor"
    # Outside the workspace directory, so cargo does not make them members.
    mkdir -p "$work/ws/shipped/src" "$work/ws/admitted/src" "$work/vendor/shared/src"
    local name
    for name in tokio raft; do
        mkdir -p "$work/vendor/$name/src"
        printf '[package]\nname = "%s"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n' \
            "$name" >"$work/vendor/$name/Cargo.toml"
        : >"$work/vendor/$name/src/lib.rs"
    done
    # A dependency with an optional Tokio feature, as a shared library.
    printf '[package]\nname = "shared"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n[dependencies]\ntokio = { path = "../tokio", optional = true }\n\n[features]\nrt = ["dep:tokio"]\n' \
        >"$work/vendor/shared/Cargo.toml"
    : >"$work/vendor/shared/src/lib.rs"
    printf '[workspace]\nmembers = ["shipped", "admitted"]\nresolver = "2"\n' >"$work/ws/Cargo.toml"
    printf '[package]\nname = "shipped"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n[dependencies]\n%s\n\n[features]\n%s\n' \
        "$shipped" "$features" >"$work/ws/shipped/Cargo.toml"
    printf '[package]\nname = "admitted"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n[dependencies]\n%s\n' \
        "$admitted" >"$work/ws/admitted/Cargo.toml"
    : >"$work/ws/shipped/src/lib.rs"
    : >"$work/ws/admitted/src/lib.rs"
    "$cargo" generate-lockfile --offline --manifest-path "$work/ws/Cargo.toml" >/dev/null 2>&1
}

failures=0
# Runs the check, with `admitted` the only Tokio-admitted crate, and
# compares byte for byte everything it wrote (stdout and stderr, kept in a
# file so no trailing newline is lost) and its exit code with the
# diagnostics wanted: a negative control passes only when the check failed
# with exactly those lines, and a clean one only when it passed silently.
# A failure for another reason (a cargo failure, an empty tree) is reported
# apart (karyos#953 review). Arguments after the label: graph, then the
# line naming the crate, repeated.
expect() {
    local label="$1"
    shift
    : >"$work/wanted"
    while [ $# -gt 0 ]; do
        printf 'check-shipped-graph: %s reaches a crate it may not ship:\n  %s\n' "$1" "$2" >>"$work/wanted"
        shift 2
    done
    local rc=0 code=0
    CARGO="$cargo" "$here/check-shipped-graph.sh" --manifest-path "$work/ws/Cargo.toml" \
        --package shipped --tokio-admitted admitted >"$work/got" 2>&1 || rc=$?
    if [ -s "$work/wanted" ]; then code=1; fi
    if [ "$rc" -eq "$code" ] && cmp -s "$work/wanted" "$work/got"; then
        return
    fi
    failures=1
    if [ "$rc" -ne 0 ] && ! grep -q 'reaches a crate it may not ship' "$work/got"; then
        echo "check-shipped-graph-selftest: $label: the check failed for another reason (exit $rc):" >&2
    else
        echo "check-shipped-graph-selftest: $label: expected (exit $code):" >&2
        cat "$work/wanted" >&2
        echo "got (exit $rc):" >&2
    fi
    cat "$work/got" >&2
}

tokio_dep='tokio = { path = "../../vendor/tokio" }'
raft_dep='raft = { path = "../../vendor/raft" }'
ws="the workspace"
every="the workspace, every feature"

make_workspace "$tokio_dep" ''
expect "a plain dependency on tokio" \
    "$ws" "tokio, from shipped" "$every" "tokio, from shipped" \
    "shipped" "tokio" "shipped, every feature" "tokio"
make_workspace 'tokio = { path = "../../vendor/tokio", optional = true }' 'experimental = ["dep:tokio"]'
# Only the every-feature graphs reach it: they are what this control proves.
expect "an optional tokio behind a nondefault feature" \
    "$every" "tokio, from shipped" "shipped, every feature" "tokio"
# Tokio where it is admitted: allowed.
make_workspace '' '' "$tokio_dep"
expect "tokio in the admitted crate only"
# A crate reaching Tokio through the admitted one is still refused.
make_workspace 'admitted = { path = "../admitted" }' '' "$tokio_dep"
expect "tokio through the admitted crate" \
    "$ws" "tokio, from shipped" "$every" "tokio, from shipped" \
    "shipped" "tokio" "shipped, every feature" "tokio"
# A shared dependency whose optional Tokio feature only the admitted crate
# turns on: the workspace build unifies it, so the other member ships
# Tokio too (karyos#953 review). Its own graph alone does not show it.
make_workspace 'shared = { path = "../../vendor/shared" }' '' \
    'shared = { path = "../../vendor/shared", features = ["rt"] }'
expect "tokio through a feature the admitted crate unifies" \
    "$ws" "tokio, from shipped" "$every" "tokio, from shipped"
# A candidate is refused everywhere, the admitted crate included.
make_workspace '' '' "$raft_dep"
expect "a candidate in the admitted crate" \
    "$ws" "raft" "$every" "raft"
make_workspace '' ''
expect "no forbidden dependency"
exit $failures
