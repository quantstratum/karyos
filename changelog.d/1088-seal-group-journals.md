### Added

- With sealing on, the running Archive seals each recording group's journal in an integrity journal in the group journal directory, at most 1 MiB per seal, so `karyos-catalog verify <groups dir>` reports the group journals' ranges with their outcomes (karyos#1088).
