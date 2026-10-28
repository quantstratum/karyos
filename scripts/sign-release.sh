#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Signs the release artifacts of scripts/release-libkaryos.sh, each on its
# own, with key-based cosign (karyos-deploy ADR-0003, decision DEP-Q2;
# karyos#700), and verifies each signature back with the public key.
#
# Run by the release key's custodian. The key lives on a hardware token
# and is named by its URI in KARYOS_RELEASE_KEY (for example
# `pkcs11:...`); the public key by KARYOS_RELEASE_PUBKEY. There is no
# fallback: without both, or without cosign, it refuses, and it never
# creates, imports or reads a key from a file of this repository. Until
# karyos-deploy's D1 gates (the R8 record for cosign, the custody
# procedure) are met, no key exists and this step does not run.
#
# Usage: scripts/sign-release.sh [DIR] (default target/release-artifacts).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
dir="${1:-${CARGO_TARGET_DIR:-$root/target}/release-artifacts}"

fail() {
    echo "sign-release: $*" >&2
    exit 1
}

[ -n "${KARYOS_RELEASE_KEY:-}" ] ||
    fail "no KARYOS_RELEASE_KEY: the release key's URI is required, and there is no fallback"
[ -n "${KARYOS_RELEASE_PUBKEY:-}" ] ||
    fail "no KARYOS_RELEASE_PUBKEY: each signature is verified with the public key"
command -v cosign >/dev/null 2>&1 || fail "cosign is not installed"
[ -f "$dir/SHA256SUMS" ] || fail "$dir is not a release directory (no SHA256SUMS)"
(cd "$dir" && shasum -a 256 -c SHA256SUMS) || fail "the artifacts do not match SHA256SUMS"

for artifact in "$dir"/*.tar.gz; do
    cosign sign-blob --yes --tlog-upload=false --key "$KARYOS_RELEASE_KEY" \
        --output-signature "$artifact.sig" "$artifact"
    cosign verify-blob --insecure-ignore-tlog --key "$KARYOS_RELEASE_PUBKEY" \
        --signature "$artifact.sig" "$artifact"
done
echo "signed and verified: $(cd "$dir" && ls ./*.tar.gz | tr '\n' ' ')"
