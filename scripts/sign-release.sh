#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Signs the release artifacts of scripts/release-libkaryos.sh, each on its
# own, with key-based cosign (karyos-deploy ADR-0003, decision DEP-Q2;
# karyos#700), and verifies each signature back with the public key.
#
# Run by the release key's custodian. The key lives on a hardware token
# and is named by its PKCS #11 URI in KARYOS_RELEASE_KEY (`pkcs11:...`);
# anything else, a key file's path included, is refused (ADR-0003's
# custody: a hardware token only; another KMS needs its own decision and
# a change here). The public key is KARYOS_RELEASE_PUBKEY. There is no
# fallback: without both, or without cosign, it refuses, and it never
# creates, imports or reads a key from a file. It signs exactly the
# archives SHA256SUMS lists, after checking them, and refuses a directory
# holding an archive it does not list. Until
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
case "$KARYOS_RELEASE_KEY" in
pkcs11:?*) ;;
*) fail "KARYOS_RELEASE_KEY is not a pkcs11: URI: the release key is on a hardware token, never in a file" ;;
esac
[ -n "${KARYOS_RELEASE_PUBKEY:-}" ] ||
    fail "no KARYOS_RELEASE_PUBKEY: each signature is verified with the public key"
command -v cosign >/dev/null 2>&1 || fail "cosign is not installed"
[ -f "$dir/SHA256SUMS" ] || fail "$dir is not a release directory (no SHA256SUMS)"
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$dir" && sha256sum -c SHA256SUMS) || fail "the artifacts do not match SHA256SUMS"
else
    (cd "$dir" && shasum -a 256 -c SHA256SUMS) || fail "the artifacts do not match SHA256SUMS"
fi

listed="$(awk '{print $2}' "$dir/SHA256SUMS" | sed 's/^\*//' | LC_ALL=C sort)"
[ -n "$listed" ] || fail "$dir/SHA256SUMS lists nothing"
archives="$(cd "$dir" && find . -mindepth 1 -maxdepth 1 -name '*.tar.gz' | sed 's|^\./||' | LC_ALL=C sort)"
[ "$archives" = "$listed" ] ||
    fail "$dir holds archives SHA256SUMS does not list, or lacks one it lists"

while read -r name; do
    artifact="$dir/$name"
    cosign sign-blob --yes --tlog-upload=false --key "$KARYOS_RELEASE_KEY" \
        --output-signature "$artifact.sig" "$artifact"
    cosign verify-blob --insecure-ignore-tlog --key "$KARYOS_RELEASE_PUBKEY" \
        --signature "$artifact.sig" "$artifact"
    echo "signed and verified: $name"
done <<<"$listed"
