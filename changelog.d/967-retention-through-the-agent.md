### Added

- The Archive agent answers `HoldRecording`, `ReleaseHold`, `PurgeRecording` and `VerifyRecording` from its own retention engine and seal verifier, so `karyosd --archive` serves them end to end: the operations journal and pending holds ledger live in the archive directory, a purge is refused `legal_hold` under a hold and `no_policy` until a purge policy is configured, and a verification reports each range of the recording (karyos#967).
