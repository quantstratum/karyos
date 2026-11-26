#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The rolling-upgrade evidence of SPEC.md section 9's third rule
# (karyos#716): before activation, a node runs a new binary only with
# evidence. One command, per upgrade:
#
#   scripts/upgrade-evidence.sh <old-rev> <new-rev> <log-dir> [options]
#
#     --geometry <term>,<segment>  the log's geometry [65536,65536]
#     --seeds <first>..<last>      the differential test's seeds [1..64]
#     --count <n>                  entries per seed [2000]
#     --max-service <n>            the highest service version generated
#                                  Activations and stops name [1]
#     --old-supported <n>, --new-supported <n>
#                                  the reference service's versions [1, 2]
#     --out <dir>                  where the evidence goes
#                                  [target/upgrade-evidence/<old>-<new>]
#
# It builds `karyos-tools` at both revisions (each in its own git worktree,
# removed at the end), and with each:
#   0. writes its `--versions` object. Before any replay counts, the new
#      build's `karyos-tools compat` decides the pair in both directions
#      (R-CORE-36, karyos#732); anything but interoperate on every
#      surface the pair uses fails it (exit 1). Both decision objects are
#      kept with the evidence;
#   1. replays a copy of the recorded Cluster log in <log-dir> (from index
#      1) into a recording group journal: each entry's payload and its
#      typed outcome, then the composed snapshot;
#   2. replays each seed's generated command sequence the same way,
#      unknown command types, schemas, schema versions and templates
#      included.
# Then it compares each pair with `karyos-replay diff` (SPEC.md 8.3):
#   karyos-replay diff <out>/old/log 1 <out>/new/log 1 --accept-manifest
# and one such diff per seed. Any difference, or a pair that is not
# comparable, fails it (exit 1). The evidence, recorded in
# <out>/evidence.txt with the upgrade: the log replayed, both revisions,
# the seeds, the two compat decisions and every diff's result.
#
# What a clean result does not say (karyos/testing/
# contract-traceability-phase-3.md, the output diff row; plan issue 071):
# the diff compares records, and a captured output by its length and
# CRC-32C, not byte by byte. The outcomes are compared as the text of
# their typed values (Debug), so a change of that text alone shows as a
# difference. The generated inputs are what the seeds draw, not every
# input. Every field of every outcome is compared, with no normalisation.
#
# A service's declaration (its supported_version or required_version
# included) is not evidence (SPEC.md:711): only a clean run of this
# command is.
set -euo pipefail

usage() { sed -n '4,20p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
[ $# -ge 3 ] || usage
old_rev=$1 new_rev=$2 log_dir=$3
shift 3
geometry=65536,65536 seeds=1..64 count=2000 max_service=1
old_supported=1 new_supported=2 out=
while [ $# -gt 0 ]; do
    [ $# -ge 2 ] || usage
    case $1 in
        --geometry) geometry=$2 ;;
        --seeds) seeds=$2 ;;
        --count) count=$2 ;;
        --max-service) max_service=$2 ;;
        --old-supported) old_supported=$2 ;;
        --new-supported) new_supported=$2 ;;
        --out) out=$2 ;;
        *) usage ;;
    esac
    shift 2
done
first=${seeds%..*} last=${seeds#*..}
[ -d "$log_dir" ] || { echo "upgrade-evidence: no log at $log_dir" >&2; exit 2; }

root=$(git rev-parse --show-toplevel)
old=$(git -C "$root" rev-parse --verify "$old_rev^{commit}")
new=$(git -C "$root" rev-parse --verify "$new_rev^{commit}")
out=${out:-$root/target/upgrade-evidence/${old:0:12}-${new:0:12}}
rm -rf "$out"
mkdir -p "$out"
work=$(mktemp -d "${TMPDIR:-/tmp}/karyos-upgrade-evidence.XXXXXX")
cleanup() {
    for side in old new; do
        [ -d "$work/$side" ] && git -C "$root" worktree remove --force "$work/$side" >/dev/null 2>&1
    done
    rm -rf "$work"
}
trap cleanup EXIT

target=${CARGO_TARGET_DIR:-$root/target}
for side in old new; do
    rev=$old supported=$old_supported
    [ $side = new ] && rev=$new supported=$new_supported
    git -C "$root" worktree add --detach "$work/$side" "$rev" >/dev/null
    (cd "$work/$side" && CARGO_TARGET_DIR=$target/upgrade-evidence-$side \
        cargo build --locked --quiet -p karyos-tools --bin karyos-tools)
    tools=$target/upgrade-evidence-$side/debug/karyos-tools
    mkdir -p "$out/$side"
    "$tools" --versions >"$out/$side/versions.json"
    cp -R "$log_dir" "$work/log-$side"
    "$tools" upgrade-evidence replay --log "$work/log-$side" --geometry "$geometry" \
        --supported "$supported" --manifest "$side $rev" --out "$out/$side/log"
    for seed in $(seq "$first" "$last"); do
        "$tools" upgrade-evidence generate --seed "$seed" --count "$count" \
            --max-service "$max_service" --supported "$supported" \
            --manifest "$side $rev" --out "$out/$side/seed-$seed"
    done
done
replay=$target/upgrade-evidence-new/debug/karyos-tools

# The wire compatibility matrix first (R-CORE-36, karyos#732): the two
# builds' --versions objects, in both directions, by the new build's
# matrix, must interoperate on every surface the pair uses before the
# replay counts as evidence. Both decisions are kept with the evidence.
compat_failed=0
for pair in old-new new-old; do
    from=${pair%-*} to=${pair#*-} code=0
    "$replay" compat "$out/$from/versions.json" "$out/$to/versions.json" \
        >"$out/compat-$pair.json" 2>&1 || code=$?
    [ "$code" -eq 0 ] || compat_failed=1
    echo "compat $from -> $to: exit $code" >>"$work/compat.txt"
done

evidence=$out/evidence.txt
{
    echo "rolling-upgrade evidence (SPEC.md section 9; karyos#716)"
    echo "log:      $(cd "$log_dir" && pwd)"
    echo "old:      $old (supported $old_supported)"
    echo "new:      $new (supported $new_supported)"
    echo "seeds:    $first..$last, $count entries each, max service $max_service"
    echo "geometry: $geometry"
    echo "compared with: karyos-tools replay diff (karyos-replay diff) at $new"
    cat "$work/compat.txt"
    echo "compat decisions: $out/compat-old-new.json, $out/compat-new-old.json"
} >"$evidence"
if [ $compat_failed -ne 0 ]; then
    echo "result:   NOT COMPATIBLE: karyos-tools compat does not decide interoperate both ways; not evidence for this upgrade" >>"$evidence"
    cat "$evidence"
    exit 1
fi
failed=0
compare() {
    local name=$1 code=0 result
    result=$("$replay" replay diff "$out/old/$name" 1 "$out/new/$name" 1 --accept-manifest 2>&1) || code=$?
    echo "$name: exit $code: $result" | head -c 2000 >>"$evidence"
    echo >>"$evidence"
    [ "$code" -eq 0 ] || failed=1
}
compare log
for seed in $(seq "$first" "$last"); do
    compare "seed-$seed"
done
if [ $failed -eq 0 ]; then
    echo "result:   identical" >>"$evidence"
else
    echo "result:   DIFFERENT: not evidence for this upgrade" >>"$evidence"
fi
cat "$evidence"
exit $failed
