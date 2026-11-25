### Added

- `karyos-backup export|verify|rebuild` (karyos#717): a stopped Cluster node's backup to a remote directory, its check and a rebuild from it, over `karyos_cluster::backup`; each command reports the index and term reached and what is not included, and a damaged object is refused naming its range.
