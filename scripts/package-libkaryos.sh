#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Packages libkaryos, the C ABI of karyos-ffi (SPEC.md §10.2; ADR-0053),
# for the language bindings (quantstratum-docs:
# karyos/design/bindings-plan.md, batch B1) into one directory:
#
#   include/karyos.h
#   lib/libkaryos.a
#   lib/libkaryos.so.X.Y.Z, .so.<soname>, .so      (Linux)
#   lib/libkaryos.<soname>.dylib, libkaryos.dylib  (macOS)
#   lib/pkgconfig/karyos.pc
#   lib/pkgconfig/karyos-static.pc                 (links lib/libkaryos.a)
#   share/karyos/conformance/                      (the suite of this commit)
#   share/karyos/MANIFEST                          (versions and build)
#   share/karyos/abi-manifest.txt                  (scripts/abi-manifest.sh)
#   share/karyos/versions.json                     (`karyos-tools --versions`)
#   LICENSE.md
#
# The crate's library is `karyos_ffi` (`karyos` would collide with the
# facade's rlib), so the libraries are built with `cargo rustc` and
# renamed here. Then the package is checked: the exported symbols against
# the header, the soname or install name, no RPATH or RUNPATH, and the
# pkg-config file where pkg-config is installed. It compiles no C.
#
# Soname policy (`soname_policy` in MANIFEST): the shared library's soname
# (Linux) or install name and compatibility version (macOS) carry
# MAJOR.MINOR of the ABI before 1.0, where a minor may break, and MAJOR
# from 1.0 on. This is the ruling of owner item 48
# (quantstratum-docs: owner-decisions/2026-10-21/decisions.md:208):
# additive compatible growth increments `0.y.z`, a binding requires the
# exact `0.y` line and a library patch at least its header's, and a
# breaking change increments `y` (karyos#700).
#
# The package is the library alone (owner item 44): no karyosd and no
# other binary, which MANIFEST states (`contents`, `excludes`) and a check
# below enforces. The conformance test kit is built beside it by
# scripts/package-testkit.sh and is not a release package.
#
# It builds for the host only (`--release --locked`; the release profile
# unwinds, as lint-sync checks); a CARGO_BUILD_TARGET other than the host
# is refused. A tree with uncommitted changes is packaged with
# core_dirty=1 and a warning, or refused when KARYOS_PACKAGE_REQUIRE_CLEAN=1
# (for a release step).
#
# Usage: scripts/package-libkaryos.sh [DEST] (default target/libkaryos).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cargo="${CARGO:-cargo}"
target_dir="${CARGO_TARGET_DIR:-$root/target}"
dest="${1:-$target_dir/libkaryos}"
case "$dest" in
/*) ;;
*) dest="$PWD/$dest" ;;
esac
# Without trailing slashes, so the stage lands beside DEST, not in it.
while [ "$dest" != / ] && [ "${dest%/}" != "$dest" ]; do dest="${dest%/}"; done
header="$root/crates/karyos-ffi/include/karyos.h"

fail() {
    echo "package-libkaryos: $*" >&2
    exit 1
}

# DEST is replaced at the end, so it must be absent or a previous
# package (its MANIFEST), and never / or $HOME.
if [ "$dest" = / ] || [ "$dest" = "${HOME%/}" ]; then
    fail "refusing DEST $dest"
fi
if [ -e "$dest" ] && [ ! -f "$dest/share/karyos/MANIFEST" ]; then
    fail "$dest exists and is not a libkaryos package; remove it or pick another DEST"
fi

define() {
    sed -n "s/^#define $1 \\([0-9][0-9]*\\)\$/\\1/p" "$header"
}
major="$(define KARYOS_ABI_VERSION_MAJOR)"
minor="$(define KARYOS_ABI_VERSION_MINOR)"
patch="$(define KARYOS_ABI_VERSION_PATCH)"
if [ -z "$major" ] || [ -z "$minor" ] || [ -z "$patch" ]; then
    fail "no KARYOS_ABI_VERSION_* in $header"
fi
abi="$major.$minor.$patch"
if [ "$major" = 0 ]; then
    soversion="$major.$minor"
    soname_policy="0y-exact"
else
    soversion="$major"
    soname_policy="major"
fi
protocol="$(sed -n 's/^pub const VERSION: u64 = \([0-9][0-9]*\);$/\1/p' \
    "$root/crates/karyos-protocol/src/admission.rs")"
[ -n "$protocol" ] || fail "no admission VERSION in karyos-protocol"
core_version="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$root/Cargo.toml" | head -n 1)"
commit="$(git -C "$root" rev-parse HEAD)"
if [ -n "$(git -C "$root" status --porcelain)" ]; then
    [ "${KARYOS_PACKAGE_REQUIRE_CLEAN:-0}" != 1 ] ||
        fail "the tree has uncommitted changes (KARYOS_PACKAGE_REQUIRE_CLEAN=1)"
    echo "package-libkaryos: warning: the tree has uncommitted changes; MANIFEST says core_dirty=1" >&2
    dirty=1
else
    dirty=0
fi
triple="$(rustc -vV | sed -n 's/^host: //p')"
if [ -n "${CARGO_BUILD_TARGET:-}" ] && [ "$CARGO_BUILD_TARGET" != "$triple" ]; then
    fail "cross builds are not packaged: CARGO_BUILD_TARGET=$CARGO_BUILD_TARGET, host $triple"
fi
# The suite's formats, from FORMAT.md's marker line (never its title):
# conformance_formats lists them all, and conformance_format keeps its
# meaning of one number, the newest format a runner needs.
formats="$("$root/scripts/conformance-formats.sh")" ||
    fail "no conformance formats in conformance/FORMAT.md"
format="${formats##* }"

case "$(uname -s)" in
Linux)
    shared="libkaryos_ffi.so"
    real="libkaryos.so.$abi"
    soname="libkaryos.so.$soversion"
    link_name="libkaryos.so"
    id_args=("-C" "link-arg=-Wl,-soname,$soname")
    ;;
Darwin)
    shared="libkaryos_ffi.dylib"
    real="libkaryos.$soversion.dylib"
    soname="@rpath/$real"
    link_name="libkaryos.dylib"
    id_args=("-C" "link-arg=-Wl,-install_name,$soname"
        "-C" "link-arg=-Wl,-compatibility_version,$soversion"
        "-C" "link-arg=-Wl,-current_version,$abi")
    ;;
*) fail "unsupported platform $(uname -s)" ;;
esac

cd "$root"
static_log="$(mktemp)"
# The package is built and checked beside DEST, and replaces it only when
# every check passed.
stage="$dest.partial.$$"
trap 'rm -f "$static_log"; rm -rf "$stage"' EXIT
"$cargo" rustc -p karyos-ffi --lib --release --locked --crate-type staticlib \
    -- --print native-static-libs 2>"$static_log" ||
    { cat "$static_log" >&2; fail "the staticlib build failed"; }
# Cargo replays the note when the staticlib is fresh.
native="$(sed -n 's/^note: native-static-libs: //p' "$static_log" | tail -n 1)"
[ -n "$native" ] || fail "rustc printed no native-static-libs for the staticlib"
"$cargo" rustc -p karyos-ffi --lib --release --locked --crate-type cdylib \
    -- "${id_args[@]}"

release="$target_dir/release"
mkdir -p "$stage/include" "$stage/lib/pkgconfig" "$stage/share/karyos"
cp "$header" "$stage/include/karyos.h"
cp "$release/libkaryos_ffi.a" "$stage/lib/libkaryos.a"
cp "$release/$shared" "$stage/lib/$real"
if [ "$(uname -s)" = Linux ]; then
    ln -s "$real" "$stage/lib/$soname"
    ln -s "$soname" "$stage/lib/$link_name"
else
    ln -s "$real" "$stage/lib/$link_name"
fi
# The suite's files (FORMAT.md, Files): the format, the scenarios and the
# coverage index; no runner.
mkdir -p "$stage/share/karyos/conformance"
cp "$root/crates/karyos-ffi/conformance/FORMAT.md" \
    "$root/crates/karyos-ffi/conformance/index.txt" "$stage/share/karyos/conformance/"
cp -R "$root/crates/karyos-ffi/conformance/scenarios" "$stage/share/karyos/conformance/scenarios"
cp "$root/LICENSE.md" "$stage/LICENSE.md"
# The released header's ABI manifest, measured on this host
# (karyos#700): what a binding asserts its declarations against.
"$root/scripts/abi-manifest.sh" "$stage/include/karyos.h" >"$stage/share/karyos/abi-manifest.txt" ||
    fail "the ABI manifest could not be measured"

# Every contract version of this commit (R-CORE-33, karyos#729), as the
# tools report them with `--versions`: written by this build's binary,
# since the package carries none, and checked against MANIFEST below.
"$cargo" build -q -p karyos-tools --bin karyos-tools --release --locked ||
    fail "the karyos-tools build failed"
"$release/karyos-tools" --versions >"$stage/share/karyos/versions.json" ||
    fail "karyos-tools --versions failed"
for pair in "\"version\":\"$abi\"" "\"admission\":$protocol," "\"release\":\"$core_version\""; do
    grep -qF "$pair" "$stage/share/karyos/versions.json" ||
        fail "versions.json disagrees with MANIFEST: no $pair"
done

cat >"$stage/lib/pkgconfig/karyos.pc" <<EOF
prefix=\${pcfiledir}/../..
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: karyos
Description: The Karyos C ABI (libkaryos), ABI version $abi
Version: $abi
Requires.private:
Libs: -L\${libdir} -lkaryos
Libs.private: $native
Cflags: -I\${includedir}
EOF

# karyos.pc's `-lkaryos` makes the linker pick the shared library even
# under `pkg-config --static` (macOS ld, and GNU ld without -Bstatic), so
# a static link names the archive itself. The archive's system libraries
# are in Libs, not Libs.private: cgo's `#cgo pkg-config:` runs
# `pkg-config --libs` without --static, and this file is only for a
# static link. Static means libkaryos only: the system libraries
# (libgcc_s on Linux, libSystem on macOS) stay dynamic.
cat >"$stage/lib/pkgconfig/karyos-static.pc" <<EOF
prefix=\${pcfiledir}/../..
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: karyos-static
Description: The Karyos C ABI (libkaryos) linked statically, ABI version $abi
Version: $abi
Libs: \${libdir}/libkaryos.a $native
Cflags: -I\${includedir}
EOF

cat >"$stage/share/karyos/MANIFEST" <<EOF
abi_version=$abi
soname=$soname
soname_policy=$soname_policy
protocol_version=$protocol
conformance_format=$format
conformance_formats=$formats
core_version=$core_version
core_commit=$commit
core_dirty=$dirty
target=$triple
rustc=$(rustc -V)
profile=release
pkg_config=karyos.pc karyos-static.pc
abi_manifest=share/karyos/abi-manifest.txt
versions=share/karyos/versions.json
contents=library
excludes=karyosd
EOF

# The library alone (owner item 44): no executable and no karyosd.
if [ -e "$stage/bin" ] || [ -n "$(find "$stage" -name 'karyosd*' -print -quit)" ]; then
    fail "the package holds a binary or karyosd; it ships the library only"
fi

# The functions the header declares: one declaration per line, starting
# with its return type (the hand-written header's style, ffi-gap-analysis.md
# §4.6). Every `karyos_name(` outside comments and typedefs must be one of
# them, so a declaration in another style fails here.
declared="$(grep -oE '^(const )?[a-z_0-9]+ \*?karyos_[a-z0-9_]+\(' "$header" |
    sed -E 's/.*(karyos_[a-z0-9_]+)\($/\1/' | sort -u)"
[ -n "$declared" ] || fail "no function declarations in $header"
# The `static inline` inits (owner item 48's option A): each wraps a
# declared `_init_sized`, and its name is also an exported symbol, the one
# a binary built against an older header calls.
inline="$(grep -oE '^static inline [a-z_0-9]+ \*?karyos_[a-z0-9_]+\(' "$header" |
    sed -E 's/.*(karyos_[a-z0-9_]+)\($/\1/' | sort -u)"
declared="$(printf '%s\n%s\n' "$declared" "$inline" | sed '/^$/d' | sort -u)"
named="$(grep -vE '^[[:space:]]*(\*|/\*|//)|^typedef' "$header" |
    grep -oE '\bkaryos_[a-z0-9_]+\(' | sed 's/($//' | sort -u)"
[ "$named" = "$declared" ] ||
    fail "the header names functions outside one-line declarations: $(comm -13 <(echo "$declared") <(echo "$named") | tr '\n' ' ')"

# The karyos_ symbols a library defines, without the platform's prefix:
# `nm -gU` on macOS (external, defined; Mach-O prefixes `_`), `nm -D
# --defined-only` for the shared and `nm -g --defined-only` for the static
# library on Linux. A cdylib exports no mangled Rust symbol, so the
# shared library's karyos_ set must equal the header's, both ways.
defined() {
    if [ "$(uname -s)" = Darwin ]; then
        nm -gU "$1" 2>/dev/null | awk '{print $NF}' | sed -n 's/^_\(karyos_.*\)$/\1/p'
    else
        nm "$2" --defined-only "$1" 2>/dev/null | awk '{print $NF}' | grep '^karyos_'
    fi | sort -u
}
exported="$(defined "$stage/lib/$real" -D)"
if [ "$exported" != "$declared" ]; then
    diff <(echo "$declared") <(echo "$exported") >&2 || true
    fail "the shared library exports other karyos_ symbols than the header declares (< header, > library)"
fi
missing="$(comm -23 <(echo "$declared") <(defined "$stage/lib/libkaryos.a" -g))"
[ -z "$missing" ] || fail "the static library lacks: $missing"

if [ "$(uname -s)" = Linux ]; then
    recorded="$(readelf -d "$stage/lib/$real" | sed -n 's/.*(SONAME).*\[\(.*\)\]$/\1/p')"
else
    recorded="$(otool -D "$stage/lib/$real" | sed -n '2p')"
fi
[ "$recorded" = "$soname" ] || fail "the shared library's name is '$recorded', not '$soname'"
if [ "$(uname -s)" = Linux ]; then
    ! readelf -d "$stage/lib/$real" | grep -qE '\((RPATH|RUNPATH)\)' ||
        fail "the shared library carries an RPATH or RUNPATH"
else
    ! otool -l "$stage/lib/$real" | grep -q 'cmd LC_RPATH' ||
        fail "the shared library carries an LC_RPATH"
    # otool prints three components.
    case "$soversion" in
    *.*) expected="$soversion.0" ;;
    *) expected="$soversion.0.0" ;;
    esac
    compat="$(otool -L "$stage/lib/$real" | sed -n '2p')"
    case "$compat" in
    *"compatibility version $expected, current version $abi"*) ;;
    *) fail "the shared library's versions are '$compat'" ;;
    esac
fi

if command -v pkg-config >/dev/null 2>&1; then
    version="$(PKG_CONFIG_PATH="$stage/lib/pkgconfig" pkg-config --modversion karyos)"
    [ "$version" = "$abi" ] || fail "pkg-config reads version '$version', not '$abi'"
    PKG_CONFIG_PATH="$stage/lib/pkgconfig" pkg-config --libs --cflags karyos >/dev/null ||
        fail "pkg-config cannot read karyos.pc"
    PKG_CONFIG_PATH="$stage/lib/pkgconfig" pkg-config --static --libs karyos >/dev/null ||
        fail "pkg-config cannot resolve the static libraries of karyos.pc"
    version="$(PKG_CONFIG_PATH="$stage/lib/pkgconfig" pkg-config --modversion karyos-static)"
    [ "$version" = "$abi" ] || fail "pkg-config reads karyos-static version '$version', not '$abi'"
    PKG_CONFIG_PATH="$stage/lib/pkgconfig" pkg-config --libs karyos-static |
        grep -q '/lib/libkaryos\.a' || fail "karyos-static.pc does not name lib/libkaryos.a"
    pc="pkg-config checked (karyos, karyos-static)"
else
    pc="pkg-config not installed: karyos.pc and karyos-static.pc not checked"
fi

rm -rf "$dest"
mv "$stage" "$dest"
count="$(echo "$declared" | wc -l | tr -d ' ')"
echo "libkaryos $abi (soname $soname, protocol $protocol) in $dest: $count functions; $pc"
