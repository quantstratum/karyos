#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
# The opentelemetry admission record (quantstratum-docs:
# karyos/reviews/dependency-admission-opentelemetry.md; karyos#706):
# condition 2, none of its crates in karyos-agent's normal graph nor in the
# default build's; condition 3, no TLS crate in karyos-otlp's graph, on any
# target.
set -u
check() {
  tree=$(cargo tree --locked "$@" -e normal --prefix none) || exit 1
  if printf '%s\n' "$tree" \
    | grep -E '^(opentelemetry|opentelemetry_sdk|opentelemetry-otlp|opentelemetry-http|opentelemetry-proto|prost|hyper|tokio) '; then
    echo "OTLP edge in the default graph (${1:-root} ${2:-})" >&2
    exit 1
  fi
}
check -p karyos-agent
check
tree=$(cargo tree --locked -p karyos-otlp --target all -e normal,build --prefix none) || exit 1
if printf '%s\n' "$tree" | grep -E '^(rustls|tokio-rustls|native-tls|openssl|ring|aws-lc-rs|h2|tonic|reqwest) '; then
  echo "TLS, HTTP/2 or another transport in karyos-otlp" >&2
  exit 1
fi
