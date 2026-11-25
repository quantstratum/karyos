### Added

- Backups of a Cluster node to remote storage and a rebuild from them (`karyos_cluster::backup`, karyos#717).
  - **Feature.** The module is behind karyos-cluster's `backup` feature. Only karyos-tools enables it, and `make pre-push` (`scripts/check-cluster-backup-graph.sh`) keeps it out of every data-path crate's graph.
  - **`export`.** Takes a copy of a stopped node's latest snapshot and the committed log after it, through the Archive's `ObjectStore`.
    - Before anything is put, it checks the snapshot's term against the log and that the commit reaches the snapshot. It refuses a remote that already holds an export, and fails when the manifest lookup fails for any reason other than a missing manifest.
    - Each object is read back and checked against its CRC-32C before it counts. The manifest goes last.
    - The report states the weakest retention the store enforced. `Retention::required` fails the export when the store does not enforce it.
  - **`verify`.** Checks the manifest's coverage and every object's bytes and contents. `verify_with` and `rebuild_with` also run the service's own check on each snapshot section.
  - **`rebuild`.** Writes only into empty directories, so it never installs over or purges a node's state. It checks the whole export before writing.
