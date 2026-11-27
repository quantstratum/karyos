### Added

- `karyos-backup export|verify|rebuild` (karyos#717): a stopped Cluster node's backup to a remote directory, its check, and a rebuild from it.
  - **Export from a copy.** Export copies the node's directories to a working copy first, so the node's own directories are only read.
  - **Locking.** Each command locks every directory it uses.
  - **Remote directory.** Objects are written under unique temporary names and the directory is synced. The report states `retention=Unsupported`, and `--require-retention` refuses it.
