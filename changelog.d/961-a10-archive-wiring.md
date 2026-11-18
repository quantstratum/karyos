### Added

- The running Archive seals what it records (A10; part of karyos#961): with `AgentConfig::seal_interval` set, the agent seals each durable byte of a recording in the integrity journal within the interval on its control path, seals the last range when the recording stops, and chains the catalog's start and stop records (`Catalog::collect_changes`, `Catalog::take_changes`); a failure of the integrity journal stops sealing, never a recording. `karyosd` takes `--archive-seal-interval` (default 1 s). `Sealer::untrack` drops a recording whose store failed.

### Changed

- `karyosd --archive` now requires `--archive-anchor-interval` and refuses to start an Archive without it (karyos#961): SPEC.md §8.4 makes `anchor_interval` required configuration with no default (X14). An existing invocation of `karyosd --archive` must add the option.
