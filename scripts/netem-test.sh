#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs the network fault tests (W6) in Linux Docker under tc netem: the
# container's own loopback loses, reorders, delays and duplicates
# datagrams, and the driver's network tests run over it. The host's network
# is untouched. Needs `--cap-add NET_ADMIN`; without it the run prints
# SKIPPED and fails, so a missing capability never reads as a pass. Each
# log names the kernel, the architecture and the netem profile.
#
# Usage: scripts/netem-test.sh [cargo test arguments...]
# Default: the ignored tests of karyos-driver whose path names `netem`
# (net::netem and the end-to-end net::e2e::netem), one at a time.
# KARYOS_NETEM sets the netem profile (default below). KARYOS_NETEM_MEASURE,
# passed through, enables the measurements (`net::e2e::bind_time`).
#
# The tests require KARYOS_NETEM_ACTIVE=1, which this script sets only once
# netem is in place, and the run fails if no netem test ran.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
base="${KARYOS_LINUX_IMAGE:-rust:1.99}"
image="karyos-netem:$(printf '%s' "$base" | tr -c 'A-Za-z0-9_.-' '-')"
tree="$(basename "$root" | tr -c 'A-Za-z0-9_.-\n' '-')"
sum="$(printf '%s' "$root" | cksum | cut -d ' ' -f 1)"
# The same target volume as scripts/linux-test.sh: the same code, built
# the same way.
target="${KARYOS_LINUX_TARGET:-karyos-linux-target-$tree-$sum}"
profile="${KARYOS_NETEM:-limit 100000 loss 2% reorder 10% 50% delay 1ms duplicate 1%}"
name_args=()
if [ -n "${KARYOS_LINUX_NAME:-}" ]; then
    name_args=(--name "$KARYOS_LINUX_NAME")
fi
if ! docker image inspect "$image" > /dev/null 2>&1; then
    docker build -q --build-arg BASE="$base" -t "$image" \
        -f "$root/scripts/netem.Dockerfile" "$root/scripts" > /dev/null
fi
args=("$@")
if [ ${#args[@]} -eq 0 ]; then
    args=(-p karyos-driver --lib --locked netem -- --ignored --test-threads=1 --nocapture)
fi

exec docker run --rm \
    --cap-add NET_ADMIN \
    ${name_args[@]+"${name_args[@]}"} \
    -v "$root":/work \
    -v "$target":/target \
    -v karyos-linux-cargo:/usr/local/cargo/registry \
    -e CARGO_TARGET_DIR=/target \
    -e KARYOS_NETEM_PROFILE="$profile" \
    -e KARYOS_NETEM_MEASURE="${KARYOS_NETEM_MEASURE:-}" \
    -w /work \
    "$image" \
    sh -c '
        echo "kernel $(uname -r) $(uname -m) target volume $1"
        echo "netem profile: $KARYOS_NETEM_PROFILE"
        shift
        if ! tc qdisc replace dev lo root netem $KARYOS_NETEM_PROFILE; then
            echo "SKIPPED: tc netem unavailable (needs --cap-add NET_ADMIN)"
            exit 3
        fi
        tc qdisc show dev lo
        status=0
        KARYOS_NETEM_ACTIVE=1 cargo test "$@" > /tmp/netem.log 2>&1 || status=$?
        tc qdisc del dev lo root || true
        cat /tmp/netem.log
        if [ "$status" -eq 0 ] && ! grep -Eq "test result: ok\. [1-9][0-9]* passed" /tmp/netem.log; then
            echo "FAILED: no netem test ran"
            exit 4
        fi
        exit "$status"
    ' sh "$target" "${args[@]}"
