#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The Raft candidates are admitted for evaluation only (quantstratum-docs:
# karyos/reviews/dependency-admission-raft-candidates-evaluation.md,
# conditions 2 and 3; karyos#677). They live in the separate evaluation
# workspace eval/raft-candidates and never in a shipped graph. This check
# enforces that with cargo tree rather than review: the normal and build
# graph of every workspace crate, for every target, and of karyos-tools
# (which ships karyosd) on its own, must name no candidate, no Tokio and
# not the evaluation crate.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cargo="${CARGO:-cargo}"
forbidden='^(raft|raft-proto|protobuf-build|openraft|openraft-rt|openraft-rt-tokio|openraft-macros|tokio|karyos-raft-eval)$'

status=0
check() {
    local label="$1"
    shift
    local names
    names="$(cd "$root" && "$cargo" tree "$@" -e normal,build --target all --prefix none --locked | awk '{print $1}' | sort -u)"
    if [ -z "$names" ]; then
        echo "check-shipped-graph: cargo tree listed nothing for $label" >&2
        status=1
        return
    fi
    local found
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
check "karyos-tools (karyosd)" -p karyos-tools
exit $status
