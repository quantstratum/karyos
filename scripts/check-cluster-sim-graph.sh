#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
# The simulator drives the shipped Cluster core through the interface
# karyos-cluster exposes, never the other way round (quantstratum-docs:
# karyos/issues 101, karyos#713): karyos-sim depends on karyos-cluster, so
# karyos-cluster must not reach karyos-sim in any graph. Cargo refuses a
# cycle of normal dependencies on its own; a dev-dependency could still
# close one, which this check refuses.
set -u
tree=$(cargo tree --locked -p karyos-cluster -e normal,dev,build --prefix none) || exit 1
if printf "%s\n" "$tree" | grep -E "^karyos-sim "; then
  echo "karyos-cluster reaches karyos-sim" >&2
  exit 1
fi
