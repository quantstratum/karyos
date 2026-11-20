### Added

- `karyosd --archive` takes a retention policy (`--archive-retain-for`, `--archive-purge manual|after-expiry`, `--archive-min-copies`) with the copy catalog's `--archive-copy-location`, and the Archive then serves `PurgeRecording` through its retention engine against the recording's store: refused `legal_hold`, `not_expired` or `below_min_copies` and the rest by name, or purged. A range's close time is the last modification of the newest segment holding bytes below the cutoff, so a purge is never early (karyos#1093).
