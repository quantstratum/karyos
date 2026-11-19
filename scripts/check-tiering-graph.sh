#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
# The object storage admission record (quantstratum-docs:
# karyos/reviews/dependency-admission-object-storage.md; karyos#965):
# condition 3, neither the client crate nor its stack in a data-path
# crate's normal graph nor in the default build's; condition 4, no native
# crypto and no C build in the client crate's graph, on any target.
set -u
check() {
  tree=$(cargo tree --locked "$@" -e normal --prefix none) || exit 1
  if printf '%s\n' "$tree" \
    | grep -E '^(karyos-tiering|rusty-s3|hyper|tokio|rustls|graviola) '; then
    echo "object storage client in a data-path graph (${2:-root})" >&2
    exit 1
  fi
}
for p in karyos-sys karyos-io karyos-protocol karyos-codec karyos-client \
         karyos-driver karyos-archive karyos karyos-ffi; do
  check -p "$p"
done
check
tree=$(cargo tree --locked -p karyos-tiering --target all -e normal,build --prefix none) || exit 1
if printf '%s\n' "$tree" | grep -E '^(ring|aws-lc-rs|aws-lc-sys|cc) '; then
  echo "native crypto or a C build in karyos-tiering" >&2
  exit 1
fi
