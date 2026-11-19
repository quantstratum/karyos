#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The archival test signer (karyos-archive feature `test-hooks`,
# `integrity::test_key`, which holds an ed25519-dalek `SigningKey`) is
# never enabled in a shipped build. The ed25519-dalek admission record
# (quantstratum-docs: karyos/reviews/dependency-admission-ed25519-archival.md,
# "The scope", Use) allows `SigningKey` only under `cfg(test)` or a
# `test-hooks` feature that no shipped build enables; only dev-dependencies
# may enable it (karyos#663, karyos#973).
#
# Resolves the workspace graph without dev-dependencies (normal and build
# edges, what a shipped binary or library is built from) and fails if any
# resolves karyos-archive with `test-hooks`. A negative self-test first
# forces the feature on and requires the query to see it, so the check
# cannot pass by not looking.
#
# Usage: scripts/check-archive-test-hooks-absent.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

fail() {
    echo "check-archive-test-hooks-absent: $*" >&2
    exit 1
}

# The features karyos-archive resolves with over the shipped edges, with
# any extra cargo arguments given.
features() {
    cargo tree --workspace --locked -e normal,build -f '{p} [{f}]' \
        -i karyos-archive --depth 0 "$@"
}

forced="$(features --features karyos-archive/test-hooks)" ||
    fail "cargo tree failed"
grep -q 'test-hooks' <<<"$forced" ||
    fail "self-test: forcing karyos-archive/test-hooks is not visible to the query: update this check"

shipped="$(features)" || fail "cargo tree failed"
if grep -q 'test-hooks' <<<"$shipped"; then
    fail "a shipped build enables karyos-archive/test-hooks: $shipped"
fi
echo "check-archive-test-hooks-absent: no shipped build enables karyos-archive/test-hooks"
