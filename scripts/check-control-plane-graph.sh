#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
# The agent HTTP stack's admission record (quantstratum-docs:
# karyos/reviews/dependency-admission-agent-http-stack.md; karyos#708):
# condition 3, none of its crates in karyos-agent's normal graph nor in the
# default build's; condition 4, no native crypto and no C build in the
# control-plane component's graph, on any target.
set -u
check() {
  tree=$(cargo tree --locked "$@" -e normal --prefix none) || exit 1
  if printf '%s\n' "$tree" \
    | grep -E '^(hyper|hyper-util|tokio|tokio-rustls|rustls|rustls-graviola|graviola) '; then
    echo "control-plane edge in the default graph (${1:-root} ${2:-})" >&2
    exit 1
  fi
}
check -p karyos-agent
check
tree=$(cargo tree --locked -p karyos-control --target all -e normal,build --prefix none) || exit 1
if printf '%s\n' "$tree" | grep -E '^(ring|aws-lc-rs|aws-lc-sys|cc) '; then
  echo "native crypto or a C build in karyos-control" >&2
  exit 1
fi
