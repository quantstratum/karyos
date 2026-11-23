#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The maintainer recipe of the XDP object (ADR-0038; quantstratum-docs
# karyos/reviews/dependency-admission-aya-af-xdp.md, "The XDP object").
# Builds bpf/karyos-xdp in the pinned container with the pinned nightly,
# aya-ebpf from the crate's committed Cargo.lock and the bpf-linker 0.13.0
# release binary checked against its published digest, then writes the
# object and its provenance into OUT (default build/xdp).
#
# Usage: scripts/xdp-object.sh build [OUT]   build and record provenance
#        scripts/xdp-object.sh lock          (re)generate the crate's lock
# KARYOS_XDP_REVISION names the source revision where the tree has no .git.
# Needs Docker and network access to crates.io, static.rust-lang.org and
# github.com. Never part of the default build or of make pre-push.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
mode="${1:-build}"
out="${2:-$root/build/xdp}"
image="rust:1.99@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07"
mkdir -p "$out"
# Absolute, so Docker binds the directory instead of creating a named volume.
out="$(cd "$out" && pwd)"
exec docker run --rm \
    -v "$root":/work:ro \
    -v "$out":/out \
    -e MODE="$mode" \
    -e IMAGE="$image" \
    -e REVISION="${KARYOS_XDP_REVISION:-$(git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown)}" \
    "$image" bash -euo pipefail -c '
toolchain=nightly-2026-11-10
version=0.13.0
case "$(uname -m)" in
    x86_64) arch=x86_64; digest=0e9b2b30f68898177f1cb6f0ecbfa909a82479473a49a0ef66529fd088e3e410 ;;
    aarch64) arch=aarch64; digest=248e25f5c6a7242b054bd8f705470abb7a5a79b2b7c07df347c5d7049b783452 ;;
    *) echo "no bpf-linker release binary for $(uname -m)" >&2; exit 1 ;;
esac
asset="bpf-linker-$arch-unknown-linux-musl.tar.zst"
# zstd only unpacks the archive, whose digest is checked first.
apt-get update -qq >/dev/null && apt-get install -qq -y zstd >/dev/null
curl -fsSL -o "/tmp/$asset" "https://github.com/aya-rs/bpf-linker/releases/download/v$version/$asset"
echo "$digest  /tmp/$asset" | sha256sum -c - >&2
mkdir -p /tmp/bpf-linker && tar --zstd -xf "/tmp/$asset" -C /tmp/bpf-linker
linker="$(find /tmp/bpf-linker -type f -name bpf-linker | head -n1)"
install -m 0755 "$linker" /usr/local/bin/bpf-linker
rustup toolchain install "$toolchain" --profile minimal --component rust-src >&2
cp -r /work/bpf/karyos-xdp /tmp/karyos-xdp
cd /tmp/karyos-xdp
if [ "$MODE" = lock ]; then
    cargo +"$toolchain" generate-lockfile
    cp Cargo.lock /out/Cargo.lock
    exit 0
fi
flags="--locked --release --target bpfel-unknown-none -Z build-std=core"
CARGO_TARGET_DIR=/tmp/target cargo +"$toolchain" build $flags >&2
cp /tmp/target/bpfel-unknown-none/release/karyos-xdp /out/karyos_xdp.bpf.o
{
    echo "# The provenance of karyos_xdp.bpf.o (ADR-0038), written by scripts/xdp-object.sh."
    echo "[source]"
    echo "revision = \"$REVISION\""
    echo "crate = \"bpf/karyos-xdp\""
    echo "lock_sha256 = \"$(sha256sum Cargo.lock | cut -d" " -f1)\""
    echo "source_sha256 = \"$(sha256sum src/main.rs | cut -d" " -f1)\""
    echo
    echo "[toolchain]"
    echo "channel = \"$toolchain\""
    echo "rustc_vv = \"\"\""
    rustc +"$toolchain" -vV
    echo "\"\"\""
    echo "aya_ebpf = \"$(awk "/name = \"aya-ebpf\"/{getline; print \$3}" Cargo.lock | tr -d \")\""
    echo "aya_ebpf_checksum = \"$(awk "/name = \"aya-ebpf\"/{f=1} f && /checksum/{print \$3; exit}" Cargo.lock | tr -d \")\""
    echo "bpf_linker = \"$version\""
    echo "bpf_linker_obtained = \"release binary $asset, sha256 $digest\""
    echo "bpf_linker_version = \"$(bpf-linker --version)\""
    echo
    echo "[build]"
    echo "image = \"$IMAGE\""
    echo "host = \"$(uname -m)\""
    echo "command = \"cargo +$toolchain build $flags\""
    echo "rustflags = \"${RUSTFLAGS:-}\""
    echo "target = \"bpfel-unknown-none\""
    echo
    echo "[object]"
    echo "file = \"karyos_xdp.bpf.o\""
    echo "sha256 = \"$(sha256sum /out/karyos_xdp.bpf.o | cut -d" " -f1)\""
    echo "size = \"$(stat -c %s /out/karyos_xdp.bpf.o)\""
    echo "license = \"Apache-2.0\""
    echo "program = \"karyos_xdp\""
    echo "maps = \"xsks: XSKMAP, 64 entries, key u32 queue index, value u32 socket; karyos_endpoints: HASH, 64 entries, key 20 bytes (family u8, pad u8, port [u8; 2] network order, addr [u8; 16]), value u8\""
} > /out/karyos_xdp.manifest.toml
sha256sum /out/karyos_xdp.bpf.o
'
