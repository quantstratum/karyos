### Added

- `karyosd --archive` takes a retention policy (`--archive-retain-for`, `--archive-purge manual|after-expiry`, `--archive-min-copies`) with the copy catalog's `--archive-copy-location`, and the Archive then serves `PurgeRecording` through its retention engine against the recording's store: refused `legal_hold`, `not_expired`, `below_min_copies`, `no_close_time` and the rest by name, or purged (karyos#1093).
- The catalog's `Stopped` record carries the recording's UTC close time (ADR-0093), never below an earlier stop's, chained in the integrity journal. A purge counts the retention from it, raised but never lowered by the segments' modification times, and refuses `no_close_time` without one. A catalog with such a record cannot be opened by an earlier build (karyos#1093).
