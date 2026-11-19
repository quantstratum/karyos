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
#   ACS 71206). It is checked over the whole workspace with its features
#   unified: every member from which Tokio is reachable must be admitted,
#   so a crate that reaches it through an admitted one, through a member
#   an admitted one uses, or through a feature an admitted one turns on,
#   is still refused (karyos#953 review).
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
    tree="$("$cargo" tree --quiet --manifest-path "$manifest" "$@" -e normal,build --target all --prefix none --locked)"
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

# Tokio over the whole workspace, its features unified as a workspace
# build unifies them: every workspace member from which Tokio is reachable
# must be an admitted crate. A dependency whose optional Tokio feature an
# admitted crate turns on reaches every other member that uses it, and a
# member between Tokio and an admitted crate ships it too: both are
# refused (karyos#953 review: excluding the admitted crates first, and
# then checking only the roots of the paths, each missed one of those).
# The members are those of cargo's inverted tree from tokio.
members="$("$cargo" metadata --quiet --manifest-path "$manifest" --no-deps --format-version 1 --locked |
    python3 -c 'import json,sys; print("\n".join(sorted(p["name"] for p in json.load(sys.stdin)["packages"])))')"
check_tokio() {
    local label="$1"
    shift
    local tree names reaching
    # Captured, then searched: no pipe for an early grep exit to break
    # under pipefail (karyos#953 review).
    tree="$("$cargo" tree --quiet --manifest-path "$manifest" "$@" -e normal,build --target all --prefix none --locked)"
    names="$(awk '{print $1}' <<<"$tree")"
    if ! grep -qx tokio <<<"$names"; then
        return
    fi
    tree="$("$cargo" tree --quiet --manifest-path "$manifest" "$@" -e normal,build --target all \
        --prefix none --locked -i tokio)"
    reaching="$(python3 -c '
import sys
members = set(sys.argv[1].split())
admitted = set(sys.argv[2:])
names = {line.split()[0] for line in sys.stdin.read().splitlines() if line.strip()}
print("\n".join(sorted((names & members) - admitted)))
' "$members" ${admitted[@]+"${admitted[@]}"} <<<"$tree")"
    if [ -n "$reaching" ]; then
        echo "check-shipped-graph: $label reaches a crate it may not ship:" >&2
        while IFS= read -r name; do
            echo "  tokio, from $name" >&2
        done <<<"$reaching"
        status=1
    fi
}

check "$candidates" "the workspace" --workspace
check "$candidates" "the workspace, every feature" --workspace --all-features
check_tokio "the workspace" --workspace
check_tokio "the workspace, every feature" --workspace --all-features
check "$candidates|$tokio" "$package" -p "$package"
check "$candidates|$tokio" "$package, every feature" -p "$package" --all-features
exit $status
