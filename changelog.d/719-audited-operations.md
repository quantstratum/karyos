### Changed

- A guard close or reopen, and a retention request (`legal-hold`, `hold-release`, `purge`) on an Archive recording, that the requester's role does not allow is now journalled, request then outcome refused `not_authorised`, and still answered `{"error":"forbidden"}` and never sent (karyos#719), as a refused purge of the agent's own journal already was: every request of SPEC §13's Audited operations row and its outcome are in the operations journal.

### Added

- `crates/karyos-agent/tests/audited_operations.rs`, the named contract test of the Audited operations row's unauthenticated half (karyos#719): a purge by unauthorised and authorised operators with its journal records, owner item 51's journal asymmetry for holds, releases and purges with the journal down, a relayed operator and the relay recorded apart, and every request ending in an outcome or an unknown interval.
