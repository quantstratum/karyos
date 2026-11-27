### Fixed

- A container restored from a snapshot whose session table holds a live session is never fresh, whatever the snapshot's flags say, so different logged `SessionBounds` after a snapshot install stop it with `ApplyError::BoundsDiffer` and keep the restored sessions (karyos#1019).
