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

run() {
    CARGO="$cargo" "$here/check-shipped-graph.sh" \
        --manifest-path "$work/ws/Cargo.toml" --package shipped >/dev/null 2>&1
}

failures=0
expect() {
    local wanted="$1" label="$2"
    if run; then got=pass; else got=fail; fi
    if [ "$got" != "$wanted" ]; then
        echo "check-shipped-graph-selftest: $label: expected $wanted, got $got" >&2
        failures=1
    fi
}

make_workspace 'tokio = { path = "../../vendor/tokio" }' ''
expect fail "a plain dependency on tokio"
make_workspace 'tokio = { path = "../../vendor/tokio", optional = true }' 'experimental = ["dep:tokio"]'
expect fail "an optional tokio behind a nondefault feature"
make_workspace '' ''
expect pass "no forbidden dependency"
exit $failures
