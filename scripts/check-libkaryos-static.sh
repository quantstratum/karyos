#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Checks that a libkaryos package (scripts/package-libkaryos.sh) links
# statically through its karyos-static.pc: a C program of a few lines is
# linked with `pkg-config --libs karyos-static` and with `--static`, each
# binary runs karyos_abi_version and prints the MANIFEST's ABI version,
# and `otool -L` (macOS) or `ldd` (Linux) shows no libkaryos.
#
# It compiles C, so it is a check of its own (`make libkaryos-static-check`)
# for the bindings' static builds: neither the package script nor the
# default build compiles C (README.md).
#
# Usage: scripts/check-libkaryos-static.sh [PACKAGE] (default
# target/libkaryos).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
package="${1:-${CARGO_TARGET_DIR:-$root/target}/libkaryos}"
cc="${CC:-cc}"

fail() {
    echo "check-libkaryos-static: $*" >&2
    exit 1
}

manifest="$package/share/karyos/MANIFEST"
[ -f "$manifest" ] || fail "no libkaryos package at $package (make libkaryos)"
[ -f "$package/lib/pkgconfig/karyos-static.pc" ] || fail "$package has no karyos-static.pc"
abi="$(sed -n 's/^abi_version=//p' "$manifest")"
command -v pkg-config >/dev/null 2>&1 || fail "pkg-config is not installed"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cat >"$work/version.c" <<'EOF'
#include <stdio.h>
#include <karyos.h>

int main(void) {
    uint32_t major = 0, minor = 0, patch = 0;
    if (karyos_abi_version(&major, &minor, &patch) != KARYOS_OK) {
        return 1;
    }
    printf("%u.%u.%u\n", major, minor, patch);
    return 0;
}
EOF

export PKG_CONFIG_PATH="$package/lib/pkgconfig"
for mode in plain static; do
    flags=(--cflags --libs)
    [ "$mode" = static ] && flags+=(--static)
    # Word splitting of pkg-config's output is intended.
    # shellcheck disable=SC2046
    "$cc" -o "$work/version-$mode" "$work/version.c" $(pkg-config "${flags[@]}" karyos-static) ||
        fail "the $mode link through karyos-static.pc failed"
    printed="$("$work/version-$mode")" || fail "the $mode binary failed"
    [ "$printed" = "$abi" ] || fail "the $mode binary printed '$printed', not '$abi'"
    if [ "$(uname -s)" = Darwin ]; then
        libraries="$(otool -L "$work/version-$mode")"
    else
        libraries="$(ldd "$work/version-$mode")"
    fi
    if grep -q libkaryos <<<"$libraries"; then
        echo "$libraries" >&2
        fail "the $mode binary loads libkaryos dynamically"
    fi
done
echo "libkaryos $abi in $package links statically through karyos-static.pc (plain and --static)"
