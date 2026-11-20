### Added

- `SnapshotConfig::large` (byte trigger `LARGE_EVERY_BYTES`, 1 GiB) to pair with `DedupConfig::large`, and `SnapshotConfig::check_sessions`, which refuses a byte trigger below the session table's reserved bytes so the large profile cannot run with the 256 MiB default trigger unnoticed (karyos#1002).
