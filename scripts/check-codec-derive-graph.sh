#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
# The codec derive's resolution review (karyos#661; owner decision
# 2026-10-21 item 15): `syn`, `quote` and `proc-macro2` stay compiler-side.
# No crate's runtime graph (normal edges, proc macros left out, every
# target and every feature) holds them, checked per workspace crate; and
# the derive brings no `syn` major of its own.
# Negative controls: the derive crate's own graph holds `syn`, and
# karyos-archive reaches the derive crate as a proc macro.
set -u
runtime() {
  cargo tree --locked -p "$1" --target all --all-features \
    -e normal,no-proc-macro --prefix none
}
for p in karyos-sys karyos-io karyos-protocol karyos-codec karyos-client \
         karyos-driver karyos-trace karyos-archive karyos-cluster karyos-feed karyos-sbe \
         karyos karyos-tools karyos-ffi karyos-agent; do
  tree=$(runtime "$p") || exit 1
  if printf '%s\n' "$tree" | grep -E '^(syn|quote|proc-macro2) '; then
    echo "a compile-time codec crate in $p's runtime graph" >&2
    exit 1
  fi
done
derive=$(cargo tree --locked -p karyos-codec-derive -e normal --prefix none) || exit 1
printf '%s\n' "$derive" | grep -qE '^syn v3\.' || {
  echo "negative control: the derive crate's graph shows no syn 3" >&2
  exit 1
}
archive=$(cargo tree --locked -p karyos-archive -e normal --prefix none) || exit 1
printf '%s\n' "$archive" | grep -qE '^karyos-codec-derive ' || {
  echo "negative control: karyos-archive does not reach the derive crate" >&2
  exit 1
}
# No `syn` major of its own: the derive's `syn` is the one `thiserror-impl`
# already builds on every host. (On x86_64, `curve25519-dalek-derive`
# also builds `syn` 2; that pair predates the derive.)
version=$(printf '%s\n' "$derive" | sed -n 's/^syn v\([0-9.]*\).*/\1/p' | head -n 1)
cargo tree --locked --workspace --all-features -e normal,build --prefix none \
  -i "syn@$version" | grep -qE '^thiserror-impl ' || {
  echo "the derive's syn $version is a major no other crate builds" >&2
  exit 1
}
