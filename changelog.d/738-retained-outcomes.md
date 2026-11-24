### Added

- A caller-chosen operation id is used up by its first submit that is sent: a retry (same id, operation, guard, principal and reason) is answered with the retained outcome, unsent, an unknown outcome included, which is never retried as a new operation; the same id for anything else is `operation id conflict`; past 24 h the id is a tombstone answered `operation expired`. The outcomes and tombstones are rebuilt from the operations journal at start, so a restart keeps them (R-CORE-18, karyos#738).
