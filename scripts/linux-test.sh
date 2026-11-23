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
# karyos-linux-target-<basename>-<checksum>: the basename of the
# repository root, for reading, and the POSIX cksum of its full physical
# path, so that two trees with the same basename get different volumes.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
image="${KARYOS_LINUX_IMAGE:-rust:1.99}"
tree="$(basename "$root" | tr -c 'A-Za-z0-9_.\n-' '-')"
sum="$(printf '%s' "$root" | cksum | cut -d ' ' -f 1)"
target="${KARYOS_LINUX_TARGET:-karyos-linux-target-$tree-$sum}"
# KARYOS_LINUX_PLATFORM selects another container platform, for example
# linux/amd64 under emulation. Its build artifacts get their own target
# volume, so they never replace the native ones.
platform_args=()
if [ -n "${KARYOS_LINUX_PLATFORM:-}" ]; then
    platform_args=(--platform "$KARYOS_LINUX_PLATFORM")
    target="$target-$(printf '%s' "$KARYOS_LINUX_PLATFORM" | tr -c 'A-Za-z0-9_.-' '-')"
fi
# KARYOS_LINUX_NAME names the container, so a caller can stop it.
name_args=()
if [ -n "${KARYOS_LINUX_NAME:-}" ]; then
    name_args=(--name "$KARYOS_LINUX_NAME")
fi
# The simulator's seed selection, KARYOS_URING_REQUIRED (the io_uring
# tests fail instead of skipping where io_uring is denied),
# KARYOS_URING_EXPECT_DENIED and KARYOS_XDP_REQUIRED (the XDP load test
# fails instead of skipping) pass through to the container.
env_args=()
for name in KARYOS_SIM_SEED KARYOS_SIM_SEEDS KARYOS_URING_REQUIRED KARYOS_URING_EXPECT_DENIED KARYOS_XDP_REQUIRED KARYOS_XDP_EXPECT_DENIED; do
    if [ -n "${!name+set}" ]; then
        env_args+=(-e "$name=${!name}")
    fi
done
# KARYOS_LINUX_CAPS adds Linux capabilities to the container, comma
# separated, for the tests that need one (karyos#1143: LINUX_IMMUTABLE).
cap_args=()
if [ -n "${KARYOS_LINUX_CAPS:-}" ]; then
    IFS=',' read -r -a caps <<<"$KARYOS_LINUX_CAPS"
    for cap in "${caps[@]}"; do
        cap_args+=(--cap-add "$cap")
    done
fi
# KARYOS_LINUX_SECCOMP sets the container's seccomp profile: Docker's
# default profile denies the io_uring system calls (quantstratum-docs
# karyos/design/io-uring-backend.md section 9). ci/seccomp/io-uring.json is
# that default profile plus the three io_uring calls only (IU-10); a path
# inside the tree is taken from the tree's root.
seccomp_args=()
if [ -n "${KARYOS_LINUX_SECCOMP:-}" ]; then
    profile="$KARYOS_LINUX_SECCOMP"
    if [ -f "$root/$profile" ]; then
        profile="$root/$profile"
    fi
    seccomp_args=(--security-opt "seccomp=$profile")
fi
args=("$@")
if [ ${#args[@]} -eq 0 ]; then
    args=(--workspace --locked)
fi

exec docker run --rm \
    ${platform_args[@]+"${platform_args[@]}"} \
    ${name_args[@]+"${name_args[@]}"} \
    ${seccomp_args[@]+"${seccomp_args[@]}"} \
    ${cap_args[@]+"${cap_args[@]}"} \
    -v "$root":/work \
    -v "$target":/target \
    -v karyos-linux-cargo:/usr/local/cargo/registry \
    -e CARGO_TARGET_DIR=/target \
    ${env_args[@]+"${env_args[@]}"} \
    -w /work \
    "$image" \
    sh -c 'echo "kernel $(uname -r) $(uname -m) target volume $1"; shift; cargo test "$@"' \
    sh "$target" "${args[@]}"
