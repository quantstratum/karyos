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
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${KARYOS_LINUX_IMAGE:-rust:1.99}"
args=("$@")
if [ ${#args[@]} -eq 0 ]; then
    args=(--workspace --locked)
fi

exec docker run --rm \
    -v "$root":/work \
    -v karyos-linux-target:/target \
    -v karyos-linux-cargo:/usr/local/cargo/registry \
    -e CARGO_TARGET_DIR=/target \
    -w /work \
    "$image" \
    sh -c 'echo "kernel $(uname -r) $(uname -m)"; cargo test "$@"' sh "${args[@]}"
