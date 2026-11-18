#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The Raft candidates are admitted for evaluation only (quantstratum-docs:
# karyos/reviews/dependency-admission-raft-candidates-evaluation.md,
# conditions 2 and 3; karyos#677). They live in the separate evaluation
# workspace eval/raft-candidates and never in a shipped graph. This check
# enforces that with cargo tree rather than review, over the normal and
# build graph for every target:
#
# - every workspace crate, and karyos-tools (which ships karyosd) on its
#   own, must name no candidate and not the evaluation crate;
# - Tokio is refused from the same roots except the crates it is admitted
#   for: karyos-control, under the owner-admitted HTTP stack (karyos#704,
#   ACS 71206). A crate that reaches Tokio through an admitted one is still
#   refused (karyos#953 review).
#
# Each graph is checked twice: with the default features, and with every
# feature, so an optional dependency behind a nondefault feature is caught
# too (karyos#953 review).
#
# Usage: check-shipped-graph.sh [--manifest-path <Cargo.toml>]
#        [--package <name>] [--tokio-admitted <name>]...
# The arguments point the check at another workspace, which
# check-shipped-graph-selftest.sh uses for its negative controls. Each
# --tokio-admitted replaces the default list.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cargo="${CARGO:-cargo}"
candidates='^(raft|raft-proto|protobuf-build|openraft|openraft-rt|openraft-rt-tokio|openraft-macros|karyos-raft-eval)$'
tokio='^tokio$'
manifest="$root/Cargo.toml"
package="karyos-tools"
admitted=(karyos-control)
admitted_set=0
while [ $# -gt 0 ]; do
    case "$1" in
        --manifest-path) manifest="$2"; shift 2 ;;
        --package) package="$2"; shift 2 ;;
        --tokio-admitted)
            if [ "$admitted_set" = 0 ]; then admitted=(); admitted_set=1; fi
            admitted+=("$2")
            shift 2
            ;;
        *) echo "check-shipped-graph: unknown argument $1" >&2; exit 2 ;;
    esac
done

status=0
check() {
    local forbidden="$1" label="$2"
    shift 2
    local tree names found
    # Captured first: a cargo failure stops the check, never reads as clean.
    tree="$("$cargo" tree --manifest-path "$manifest" "$@" -e normal,build --target all --prefix none --locked)"
    names="$(awk '{print $1}' <<<"$tree" | sort -u)"
    if [ -z "$names" ]; then
        echo "check-shipped-graph: cargo tree listed nothing for $label" >&2
        status=1
        return
    fi
    found="$(grep -E "$forbidden" <<<"$names" || true)"
    if [ -n "$found" ]; then
        echo "check-shipped-graph: $label reaches a crate it may not ship:" >&2
        while IFS= read -r name; do
            echo "  $name" >&2
        done <<<"$found"
        status=1
    fi
}

# The admitted crates that are members here: cargo refuses to exclude a
# package that is not one.
members="$("$cargo" metadata --manifest-path "$manifest" --no-deps --format-version 1 --locked |
    python3 -c 'import json,sys; print("\n".join(p["name"] for p in json.load(sys.stdin)["packages"]))')"
excluded=()
for name in "${admitted[@]}"; do
    if grep -qx -- "$name" <<<"$members"; then
        excluded+=(--exclude "$name")
    fi
done

check "$candidates" "the workspace" --workspace
check "$candidates" "the workspace, every feature" --workspace --all-features
check "$tokio" "the workspace but the Tokio-admitted crates" --workspace ${excluded[@]+"${excluded[@]}"}
check "$tokio" "the workspace but the Tokio-admitted crates, every feature" \
    --workspace --all-features ${excluded[@]+"${excluded[@]}"}
check "$candidates|$tokio" "$package" -p "$package"
check "$candidates|$tokio" "$package, every feature" -p "$package" --all-features
exit $status
