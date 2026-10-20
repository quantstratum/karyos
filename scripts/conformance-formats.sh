#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Prints the conformance formats the suite holds, ascending and separated
# by one space ("1 2"), from the marker line of
# crates/karyos-ffi/conformance/FORMAT.md:
#
#   <!-- conformance-formats: 1 2 -->
#
# It fails when the marker is missing, appears more than once, or holds
# anything but ascending positive integers. The package script
# (package-libkaryos.sh) and make lint-sync both read the formats here,
# so the marker is the one place they come from.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
format_md="$root/crates/karyos-ffi/conformance/FORMAT.md"

fail() {
    echo "conformance-formats: $*" >&2
    exit 1
}

[ -f "$format_md" ] || fail "no $format_md"
markers="$(grep -c '^<!-- conformance-formats: .* -->$' "$format_md" || true)"
[ "$markers" = 1 ] || fail "FORMAT.md needs exactly one '<!-- conformance-formats: N ... -->' line, found $markers"
formats="$(sed -n 's/^<!-- conformance-formats: \(.*\) -->$/\1/p' "$format_md")"
[[ "$formats" =~ ^[1-9][0-9]*(\ [1-9][0-9]*)*$ ]] ||
    fail "the marker's formats are not positive integers separated by one space: '$formats'"
previous=0
for format in $formats; do
    [ "$format" -gt "$previous" ] || fail "the marker's formats are not ascending: '$formats'"
    previous="$format"
done
echo "$formats"
