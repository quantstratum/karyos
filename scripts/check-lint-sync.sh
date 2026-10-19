#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# karyos-sys, karyos-io and karyos-ffi cannot inherit the workspace lints
# (they allow unsafe, karyos-ffi only at its boundary), so they repeat the
# clippy set. Fail if any workspace clippy lint is missing from one of them.
# For karyos-ffi (SPEC.md §10.2, §14; ADR-0053) also fail unless the crate
# denies unsafe_code, the only `expect(unsafe_code)` attributes are the one
# on `mod abi` in src/lib.rs and the one of tests/support/abi.rs, nothing
# allows unsafe_code, and no workspace profile sets panic = "abort" (the
# boundary catches panics only if libkaryos unwinds).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
workspace_lints="$(awk '/^\[workspace.lints.clippy\]/{f=1;next} /^\[/{f=0} f && /=/' "$root/Cargo.toml" | sed 's/ //g')"
status=0
for crate in karyos-sys karyos-io karyos-ffi; do
    manifest="$root/crates/$crate/Cargo.toml"
    crate_lints="$(awk '/^\[lints.clippy\]/{f=1;next} /^\[/{f=0} f && /=/' "$manifest" | sed 's/ //g')"
    while IFS= read -r lint; do
        if ! grep -qxF "$lint" <<<"$crate_lints"; then
            echo "$crate is missing workspace clippy lint: $lint" >&2
            status=1
        fi
    done <<<"$workspace_lints"
done

ffi="$root/crates/karyos-ffi"
if ! awk '/^\[lints.rust\]/{f=1;next} /^\[/{f=0} f' "$ffi/Cargo.toml" | grep -qx 'unsafe_code = "deny"'; then
    echo 'karyos-ffi must set unsafe_code = "deny" in [lints.rust]' >&2
    status=1
fi
if ! grep -qx '#!\[deny(unsafe_code)\]' "$ffi/src/lib.rs"; then
    echo 'karyos-ffi src/lib.rs must declare #![deny(unsafe_code)]' >&2
    status=1
fi
expects="$(cd "$ffi" && find src tests -name '*.rs' -print0 | sort -z | xargs -0 perl -0ne 'while (/expect\(\s*unsafe_code\b/g) { print "$ARGV\n" }')"
if [ "$expects" != "$(printf 'src/lib.rs\ntests/support/abi.rs')" ]; then
    printf 'karyos-ffi expects unsafe_code outside src/lib.rs (mod abi) and tests/support/abi.rs, or not once in each:\n%s\n' "$expects" >&2
    status=1
fi
if ! perl -0ne 'exit(/#\[expect\(\s*unsafe_code,\s*reason\s*=\s*"[^"]+",?\s*\)\]\s*mod abi;/ ? 0 : 1)' "$ffi/src/lib.rs"; then
    echo 'karyos-ffi src/lib.rs: the expect(unsafe_code, reason = "...") must sit on mod abi' >&2
    status=1
fi
if grep -rqE 'allow\(\s*unsafe_code' "$ffi/src" "$ffi/tests"; then
    echo 'karyos-ffi must not allow unsafe_code' >&2
    status=1
fi
if grep -qE '^[[:space:]]*panic[[:space:]]*=[[:space:]]*"abort"' "$root/Cargo.toml"; then
    echo 'a workspace profile sets panic = "abort"; libkaryos must unwind' >&2
    status=1
fi
exit "$status"
