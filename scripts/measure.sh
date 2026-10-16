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
#    each child pinned to an isolated core when the host has two.
#
# The allocation build (step 4 of 5.5) arrives with batch B3d, and the
# analysis and report.md (step 5) with batch B4b.
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

cargo build -p karyos-bench --release --locked
bin=$root/target/release/karyos-bench
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
"$bin" measure --plan primary --out "$out" "$@"
echo "measure: wrote $out"
