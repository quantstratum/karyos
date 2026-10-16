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
# With `--plan synthetic` (the last --plan wins) it runs the synthetic
# check instead (§5.2): step 1 builds the synthetic build (feature
# synthetic) into its own target directory, step 4 is skipped (the
# allocation step counts the primary plan), and step 5 adds
# `--interval-on-e4`. Every result of that build is report-only.
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

plan=primary
previous=
for arg in "$@"; do
    if [ "$previous" = "--plan" ]; then
        plan=$arg
    fi
    previous=$arg
done
case $plan in
    primary)
        target_dir=${CARGO_TARGET_DIR:-$root/target}
        features=()
        build="build timing"
        ;;
    synthetic)
        target_dir=${CARGO_TARGET_DIR:-$root/target}/synthetic
        features=(--features synthetic)
        build="build timing+synthetic"
        ;;
    *)
        echo "measure.sh: unknown plan $plan: primary or synthetic" >&2
        exit 2
        ;;
esac
cargo build -p karyos-bench --release --locked ${features[@]+"${features[@]}"} --target-dir "$target_dir"
# The binary this build made, wherever cargo puts its target directory:
# a stale one elsewhere must never run under the current commit.
bin=$target_dir/release/karyos-bench
# Only a timing build is timed: a build with alloc-count (an
# --all-features build included) counts allocations instead (M-9).
if [ "$("$bin" build-info)" != "$build" ]; then
    echo "measure.sh: $bin is not the $plan plan's build ($build): $("$bin" build-info)" >&2
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
if [ "$plan" = synthetic ]; then
    "$bin" analyze --out "$out" --interval-on-e4
    echo "measure: wrote $out"
    exit "$status"
fi
# Step 4 may fail without stopping step 5: a failed step is a result too.
alloc_target=${CARGO_TARGET_DIR:-$root/target}/alloc-count
alloc_bin=$alloc_target/release/karyos-bench
if cargo build -p karyos-bench --release --locked --features alloc-count --target-dir "$alloc_target" \
    && [ "$("$alloc_bin" build-info)" = "build alloc-count" ]; then
    "$alloc_bin" alloc --out "$out" || status=$?
else
    echo "measure.sh: the allocation step failed: no alloc-count binary" >&2
    status=1
fi
"$bin" analyze --out "$out"
echo "measure: wrote $out"
exit "$status"
