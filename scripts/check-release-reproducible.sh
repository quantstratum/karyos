#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Checks that scripts/release-libkaryos.sh is deterministic on this host
# (karyos#700): two builds of HEAD, one under TZ=UTC and umask 022 and
# one under TZ=Asia/Tokyo and umask 077, must give the same SHA256SUMS.
# The tree must be clean, as for a release.
#
# Usage: scripts/check-release-reproducible.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

(umask 022 && TZ=UTC "$root/scripts/release-libkaryos.sh" "$work/a") >/dev/null
(umask 077 && TZ=Asia/Tokyo "$root/scripts/release-libkaryos.sh" "$work/b") >/dev/null
if ! cmp -s "$work/a/SHA256SUMS" "$work/b/SHA256SUMS"; then
    diff "$work/a/SHA256SUMS" "$work/b/SHA256SUMS" >&2 || true
    echo "check-release-reproducible: two builds of $(git -C "$root" rev-parse --short HEAD) differ" >&2
    exit 1
fi
echo "release reproducible on this host under two TZ and umask:"
cat "$work/a/SHA256SUMS"
