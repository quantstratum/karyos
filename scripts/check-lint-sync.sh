#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# karyos-sys and karyos-io cannot inherit the workspace lints (they allow
# unsafe), so they repeat the clippy set. Fail if any workspace clippy lint is
# missing from either crate.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
workspace_lints="$(awk '/^\[workspace.lints.clippy\]/{f=1;next} /^\[/{f=0} f && /=/' "$root/Cargo.toml" | sed 's/ //g')"
status=0
for crate in karyos-sys karyos-io; do
    manifest="$root/crates/$crate/Cargo.toml"
    crate_lints="$(awk '/^\[lints.clippy\]/{f=1;next} /^\[/{f=0} f && /=/' "$manifest" | sed 's/ //g')"
    while IFS= read -r lint; do
        if ! grep -qxF "$lint" <<<"$crate_lints"; then
            echo "$crate is missing workspace clippy lint: $lint" >&2
            status=1
        fi
    done <<<"$workspace_lints"
done
exit "$status"
