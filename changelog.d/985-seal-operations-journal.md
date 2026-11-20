### Added

- The agent seals its operations journal: each durable append seals the recording to its durable end through an integrity journal in the journal's directory, so `karyos-catalog verify` reports its ranges. A failed seal stops the sealing until restart and counts in `Journal::failed_seals`; the journal goes on. `Recorder::read` reads a recorder's store back for such a seal (karyos#985).
