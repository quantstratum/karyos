### Added

- The Archive agent chains its configured retention policy (`karyosd --archive-retain-for`, `--archive-purge`, `--archive-min-copies`) in the integrity journal at start through the policy book, so the policy in force for a purged range can be shown from the chain (SPEC.md 8.4; karyos#1123). A start with changed terms records the next version, an unchanged one records nothing, and purges are checked against the recorded version. `PolicyBook::current` and `PolicyBook::record_configured` are new.
