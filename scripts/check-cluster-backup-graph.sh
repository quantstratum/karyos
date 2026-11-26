#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
# A Cluster node's backup and rebuild (karyos_cluster::backup; karyos#717)
# run on the control path only: the module is behind karyos-cluster's
# `backup` feature, which only karyos-tools enables. This check keeps the
# feature out of every data-path crate's normal graph, as
# check-tiering-graph.sh does for the object storage client. The default
# build holds karyos-tools, a control-path binary, so it holds the feature
# too; what links into a data-path process is each crate's own graph.
set -u
check() {
  tree=$(cargo tree --locked "$@" -e normal,features --prefix none) || exit 1
  if printf '%s\n' "$tree" | grep -E '^karyos-cluster feature "backup"'; then
    echo "the cluster backup in a data-path graph (${2:-root})" >&2
    exit 1
  fi
}
for p in karyos-sys karyos-io karyos-protocol karyos-codec karyos-client \
         karyos-driver karyos-archive karyos-cluster karyos karyos-ffi \
         karyos-agent; do
  check -p "$p"
done
# The check itself: karyos-tools does enable it, so a graph that holds the
# feature is seen.
tree=$(cargo tree --locked -p karyos-tools -e normal,features --prefix none) || exit 1
if ! printf '%s\n' "$tree" | grep -qE '^karyos-cluster feature "backup"'; then
  echo "the check does not see the backup feature where it is enabled" >&2
  exit 1
fi
