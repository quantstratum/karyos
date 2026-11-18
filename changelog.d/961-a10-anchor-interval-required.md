### Changed

- `karyosd --archive` now requires `--archive-anchor-interval` and refuses to start an Archive without it (karyos#961): SPEC.md §8.4 makes `anchor_interval` required configuration with no default (X14). An existing invocation of `karyosd --archive` must add the option.
