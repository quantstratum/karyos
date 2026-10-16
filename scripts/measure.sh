#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The one command of the wire measurement harness
# (quantstratum-docs: karyos/design/measurement-harness.md 5.5):
#
# 1. builds karyos-bench with --release --locked;
# 2. writes this host's inventory into the output directory and prints
#    its class and eligibility against the filed records;
# 3. runs `karyos-bench measure --plan primary` into the same directory,
#    each child pinned to an isolated core when the host has two;
# 4. builds the allocation build (feature alloc-count) into its own
#    target directory and runs `karyos-bench alloc`, which counts the
#    allocations of both stages at every point into alloc.json; that
#    build never measures timing (M-9);
# 5. runs `karyos-bench analyze`, which writes report.md and
#    analysis.json, even when runs failed: a failed run is a result.
#
# Usage: scripts/measure.sh [measure arguments...], for example
# --plan-only. Environment:
#   KARYOS_ENVIRONMENTS   the filed host records (quantstratum-docs:
#                         karyos/environments); without it no run is
#                         decision eligible
#   KARYOS_MEASURE_OUT    the output directory; default
#                         target/karyos-measure/<utc>-<commit>
#   KARYOS_MEASURE_SMOKE  1 for the smoke plan: small N, labelled
#                         "insufficient samples", never decision grade
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"
commit=$(git rev-parse --short HEAD)
utc=$(date -u +%Y%m%dT%H%M%SZ)
out=${KARYOS_MEASURE_OUT:-$root/target/karyos-measure/$utc-$commit}

for arg in "$@"; do
    if [ "$arg" = "--out" ] || [ "${arg#--out=}" != "$arg" ]; then
        echo "measure.sh: set KARYOS_MEASURE_OUT, not --out: the inventory and the runs share one directory" >&2
        exit 2
    fi
done

cargo build -p karyos-bench --release --locked
# The binary this build made, wherever cargo puts its target directory:
# a stale one elsewhere must never run under the current commit.
bin=${CARGO_TARGET_DIR:-$root/target}/release/karyos-bench
# Only a timing build is timed: a build with alloc-count (an
# --all-features build included) counts allocations instead (M-9).
if [ "$("$bin" build-info)" != "build timing" ]; then
    echo "measure.sh: $bin is not a timing build: $("$bin" build-info)" >&2
    exit 2
fi
export KARYOS_COMMIT=$commit

for arg in "$@"; do
    if [ "$arg" = "--plan-only" ]; then
        exec "$bin" measure --plan primary "$@"
    fi
done

records=()
if [ -n "${KARYOS_ENVIRONMENTS:-}" ]; then
    records=(--records "$KARYOS_ENVIRONMENTS")
fi
"$bin" inventory --out "$out" "${records[@]+"${records[@]}"}"
status=0
"$bin" measure --plan primary --out "$out" "$@" || status=$?
alloc_target=${CARGO_TARGET_DIR:-$root/target}/alloc-count
cargo build -p karyos-bench --release --locked --features alloc-count --target-dir "$alloc_target"
if [ "$("$alloc_target/release/karyos-bench" build-info)" != "build alloc-count" ]; then
    echo "measure.sh: the allocation binary is not an alloc-count build" >&2
    exit 2
fi
"$alloc_target/release/karyos-bench" alloc --out "$out" || status=$?
"$bin" analyze --out "$out"
echo "measure: wrote $out"
exit "$status"
