#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs Linux-only tests in Docker on a non-Linux development machine
# (quantstratum-docs: karyos/design/ipc-implementation.md, "Where Linux tests run"). Functional
# evidence only: the kernel is a VM kernel. Prints the kernel and
# architecture first so the evidence names them.
#
# Usage: scripts/linux-test.sh [cargo test arguments...]
# Default: cargo test --workspace --locked
#
# Every tree is mounted at the same /work path, so cargo cannot tell trees
# apart inside a shared target directory: concurrent runs from different
# worktrees replace each other's test binaries, and a log can then show
# another tree's tests. Each tree therefore gets its own target volume,
# named from KARYOS_LINUX_TARGET or, by default,
# karyos-linux-target-<basename of the repository root>.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${KARYOS_LINUX_IMAGE:-rust:1.99}"
tree="$(basename "$root" | tr -c 'A-Za-z0-9_.-\n' '-')"
target="${KARYOS_LINUX_TARGET:-karyos-linux-target-$tree}"
args=("$@")
if [ ${#args[@]} -eq 0 ]; then
    args=(--workspace --locked)
fi

exec docker run --rm \
    -v "$root":/work \
    -v "$target":/target \
    -v karyos-linux-cargo:/usr/local/cargo/registry \
    -e CARGO_TARGET_DIR=/target \
    -w /work \
    "$image" \
    sh -c 'echo "kernel $(uname -r) $(uname -m) target volume $1"; shift; cargo test "$@"' \
    sh "$target" "${args[@]}"
