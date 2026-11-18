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
    local dependency="$1" features="$2"
    rm -rf "$work/ws" "$work/vendor"
    # Outside the workspace directory, so cargo does not make it a member.
    mkdir -p "$work/ws/shipped/src" "$work/vendor/tokio/src"
    printf '[workspace]\nmembers = ["shipped"]\nresolver = "2"\n' >"$work/ws/Cargo.toml"
    printf '[package]\nname = "tokio"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n' \
        >"$work/vendor/tokio/Cargo.toml"
    : >"$work/vendor/tokio/src/lib.rs"
    printf '[package]\nname = "shipped"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n[dependencies]\n%s\n\n[features]\n%s\n' \
        "$dependency" "$features" >"$work/ws/shipped/Cargo.toml"
    : >"$work/ws/shipped/src/lib.rs"
    "$cargo" generate-lockfile --offline --manifest-path "$work/ws/Cargo.toml" >/dev/null 2>&1
}

failures=0
# Runs the check and compares, line by line, what it reported with the
# diagnostics wanted: a negative control passes only when the check failed
# for the forbidden crate in exactly the graphs named, never for another
# reason (a cargo failure, an empty tree), which is reported apart
# (karyos#953 review).
expect() {
    local label="$1"
    shift
    local wanted="" graph output rc=0
    for graph in "$@"; do
        wanted+="check-shipped-graph: $graph reaches an evaluation-only crate:"$'\n'"  tokio"$'\n'
    done
    output="$(CARGO="$cargo" "$here/check-shipped-graph.sh" \
        --manifest-path "$work/ws/Cargo.toml" --package shipped 2>&1 >/dev/null)" || rc=$?
    if [ -n "$output" ]; then output+=$'\n'; fi
    local code=0
    if [ -n "$wanted" ]; then code=1; fi
    if [ "$rc" -eq "$code" ] && [ "$output" = "$wanted" ]; then
        return
    fi
    failures=1
    if [ "$rc" -ne 0 ] && ! grep -q 'reaches an evaluation-only crate' <<<"$output"; then
        echo "check-shipped-graph-selftest: $label: the check failed for another reason (exit $rc):" >&2
    else
        echo "check-shipped-graph-selftest: $label: expected (exit $code):" >&2
        printf '%s\n' "${wanted:-  nothing}" >&2
        echo "got (exit $rc):" >&2
    fi
    printf '%s\n' "${output:-  nothing}" >&2
}

make_workspace 'tokio = { path = "../../vendor/tokio" }' ''
expect "a plain dependency on tokio" \
    "the workspace" "the workspace, every feature" "shipped" "shipped, every feature"
make_workspace 'tokio = { path = "../../vendor/tokio", optional = true }' 'experimental = ["dep:tokio"]'
# Only the every-feature graphs reach it: they are what this control proves.
expect "an optional tokio behind a nondefault feature" \
    "the workspace, every feature" "shipped, every feature"
make_workspace '' ''
expect "no forbidden dependency"
exit $failures
