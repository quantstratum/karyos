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
    mkdir -p "$work/ws/shipped/src" "$work/ws/admitted/src"
    local name
    for name in tokio raft; do
        mkdir -p "$work/vendor/$name/src"
        printf '[package]\nname = "%s"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n' \
            "$name" >"$work/vendor/$name/Cargo.toml"
        : >"$work/vendor/$name/src/lib.rs"
    done
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
# compares everything it wrote (stdout and stderr) and its exit code with
# the diagnostics wanted: a negative control passes only when the check
# failed for `crate` in exactly the graphs named, and the clean ones only
# when it passed silently. A failure for another reason (a cargo failure,
# an empty tree) is reported apart (karyos#953 review).
expect() {
    local label="$1" crate="$2"
    shift 2
    local wanted="" graph output rc=0
    for graph in "$@"; do
        wanted+="check-shipped-graph: $graph reaches a crate it may not ship:"$'\n'"  $crate"$'\n'
    done
    output="$(CARGO="$cargo" "$here/check-shipped-graph.sh" \
        --manifest-path "$work/ws/Cargo.toml" --package shipped --tokio-admitted admitted 2>&1)" || rc=$?
    if [ -n "$output" ]; then output+=$'\n'; fi
    local code=0
    if [ -n "$wanted" ]; then code=1; fi
    if [ "$rc" -eq "$code" ] && [ "$output" = "$wanted" ]; then
        return
    fi
    failures=1
    if [ "$rc" -ne 0 ] && ! grep -q 'reaches a crate it may not ship' <<<"$output"; then
        echo "check-shipped-graph-selftest: $label: the check failed for another reason (exit $rc):" >&2
    else
        echo "check-shipped-graph-selftest: $label: expected (exit $code):" >&2
        printf '%s\n' "${wanted:-  nothing}" >&2
        echo "got (exit $rc):" >&2
    fi
    printf '%s\n' "${output:-  nothing}" >&2
}

tokio_dep='tokio = { path = "../../vendor/tokio" }'
raft_dep='raft = { path = "../../vendor/raft" }'
core="the workspace but the Tokio-admitted crates"

make_workspace "$tokio_dep" ''
expect "a plain dependency on tokio" tokio \
    "$core" "$core, every feature" "shipped" "shipped, every feature"
make_workspace 'tokio = { path = "../../vendor/tokio", optional = true }' 'experimental = ["dep:tokio"]'
# Only the every-feature graphs reach it: they are what this control proves.
expect "an optional tokio behind a nondefault feature" tokio \
    "$core, every feature" "shipped, every feature"
# Tokio where it is admitted: allowed.
make_workspace '' '' "$tokio_dep"
expect "tokio in the admitted crate only" tokio
# A crate reaching Tokio through the admitted one is still refused.
make_workspace 'admitted = { path = "../admitted" }' '' "$tokio_dep"
expect "tokio through the admitted crate" tokio \
    "$core" "$core, every feature" "shipped" "shipped, every feature"
# A candidate is refused everywhere, the admitted crate included.
make_workspace '' '' "$raft_dep"
expect "a candidate in the admitted crate" raft \
    "the workspace" "the workspace, every feature"
make_workspace '' ''
expect "no forbidden dependency" tokio
exit $failures
