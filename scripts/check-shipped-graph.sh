#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The Raft candidates are admitted for evaluation only (quantstratum-docs:
# karyos/reviews/dependency-admission-raft-candidates-evaluation.md,
# conditions 2 and 3; karyos#677). They live in the separate evaluation
# workspace eval/raft-candidates and never in a shipped graph. This check
# enforces that with cargo tree rather than review: the normal and build
# graph of every workspace crate, for every target, and of karyos-tools
# (which ships karyosd) on its own, must name no candidate, no Tokio and
# not the evaluation crate. Each graph is checked twice: with the default
# features, and with every feature, so an optional dependency behind a
# nondefault feature is caught too (karyos#953 review).
#
# Usage: check-shipped-graph.sh [--manifest-path <Cargo.toml> --package <name>]
# The arguments point the check at another workspace, which
# check-shipped-graph-selftest.sh uses for its negative controls.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cargo="${CARGO:-cargo}"
forbidden='^(raft|raft-proto|protobuf-build|openraft|openraft-rt|openraft-rt-tokio|openraft-macros|tokio|karyos-raft-eval)$'
manifest="$root/Cargo.toml"
package="karyos-tools"
while [ $# -gt 0 ]; do
    case "$1" in
        --manifest-path) manifest="$2"; shift 2 ;;
        --package) package="$2"; shift 2 ;;
        *) echo "check-shipped-graph: unknown argument $1" >&2; exit 2 ;;
    esac
done

status=0
check() {
    local label="$1"
    shift
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
        echo "check-shipped-graph: $label reaches an evaluation-only crate:" >&2
        while IFS= read -r name; do
            echo "  $name" >&2
        done <<<"$found"
        status=1
    fi
}

check "the workspace" --workspace
check "the workspace, every feature" --workspace --all-features
check "$package" -p "$package"
check "$package, every feature" -p "$package" --all-features
exit $status
