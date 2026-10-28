### Changed

- `GuardRate` and `AuditOutcome` are `#[non_exhaustive]` (karyos#740).
  Build a `GuardRate` with `GuardRate::publication(policy)` (or
  `GuardRate::scoped(scope, policy)`) and `.with_reserve(rate)` for the
  new control reserve; a reserve the policy itself crosses is refused at
  `guard_stream`. `GuardSpec` has a new `policy` field, the gate's slot.
