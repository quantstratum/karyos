#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs the simulator's seed sweep in a native linux/arm64 container and in
# an emulated linux/amd64 container (Docker), both through
# scripts/linux-test.sh, so that only the architecture differs, and reports
# both outcomes and timings (issue #11, "aarch64 native against emulated runs"). The report is
# descriptive: timings are never compared against a threshold, and an
# emulated run that cannot complete on this host is reported as "not
# verifiable on this host", not as a failure. Only a failing native run
# makes the script exit non-zero. The emulated run keeps its own target
# volume, whose name and removal command the report prints.
#
# Usage: scripts/sim-arch-compare.sh
# KARYOS_SIM_SEEDS        seeds per scenario (default 2000, as `make sim`)
# KARYOS_SIM_ARCH_TIMEOUT seconds allowed for the emulated run (default 3600)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
seeds="${KARYOS_SIM_SEEDS:-2000}"
limit="${KARYOS_SIM_ARCH_TIMEOUT:-3600}"
host_arch="$(uname -m)"
case "$host_arch" in
    arm64 | aarch64) ;;
    *)
        printf 'sim-arch-compare needs an AArch64 host, found %s\n' "$host_arch" >&2
        exit 2
        ;;
esac
cd "$root"

printf 'host: %s %s\n' "$(uname -s)" "$host_arch"
printf 'seeds per scenario: %s\n' "$seeds"

# Both runs are named containers, stopped on any exit of this script, so an
# interrupted comparison leaves nothing running.
native_container="karyos-sim-arch-native-$$"
container="karyos-sim-arch-$$"
cleanup() {
    docker stop "$native_container" "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# Native run, linux/arm64 on this host: its status is the script's status.
start=$(date +%s)
set +e
KARYOS_SIM_SEED='' KARYOS_SIM_SEEDS="$seeds" KARYOS_LINUX_NAME="$native_container" \
    scripts/linux-test.sh -p karyos-sim --release --locked --test scenarios
native=$?
set -e
native_seconds=$(($(date +%s) - start))

# Emulated run, bounded by the limit. It runs in the background, so that
# the script can stop its container when the limit passes.
start=$(date +%s)
KARYOS_SIM_SEED='' KARYOS_SIM_SEEDS="$seeds" KARYOS_LINUX_PLATFORM=linux/amd64 \
    KARYOS_LINUX_NAME="$container" \
    scripts/linux-test.sh -p karyos-sim --release --locked --test scenarios &
emulated_pid=$!
emulated=''
while kill -0 "$emulated_pid" 2>/dev/null; do
    if [ $(($(date +%s) - start)) -ge "$limit" ]; then
        docker stop "$container" >/dev/null 2>&1 || true
        emulated='timeout'
        break
    fi
    sleep 5
done
set +e
wait "$emulated_pid"
emulated_status=$?
set -e
emulated_seconds=$(($(date +%s) - start))

printf '\nreport (informational; no threshold)\n'
if [ "$native" -eq 0 ]; then
    printf 'native linux/arm64: passed in %s s\n' "$native_seconds"
else
    printf 'native linux/arm64: FAILED (exit %s) after %s s\n' "$native" "$native_seconds"
fi
if [ "$emulated" = 'timeout' ]; then
    printf 'emulated linux/amd64: not verifiable on this host (stopped after %s s)\n' "$limit"
elif [ "$emulated_status" -eq 0 ]; then
    printf 'emulated linux/amd64: passed in %s s\n' "$emulated_seconds"
else
    printf 'emulated linux/amd64: not verifiable on this host (exit %s after %s s)\n' \
        "$emulated_status" "$emulated_seconds"
fi
tree="$(basename "$root" | tr -c 'A-Za-z0-9_.-\n' '-')"
sum="$(printf '%s' "$root" | cksum | cut -d ' ' -f 1)"
printf 'emulated target volume: karyos-linux-target-%s-%s-linux-amd64\n' "$tree" "$sum"
printf 'remove it with: docker volume rm karyos-linux-target-%s-%s-linux-amd64\n' "$tree" "$sum"
exit "$native"
