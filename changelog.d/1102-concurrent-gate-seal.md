### Added

- Guard support in the concurrent log buffer, part (a) of karyos#1102 (ADR-0092).
  - **`Gated` variants.** A concurrent handle that meets a gate seal (guard close, missed deadline or schedule violation) now reports `ConcurrentOfferOutcome::Gated` or `ConcurrentClaimOutcome::Gated`, as an exclusive one reports `Gated`, instead of `Closed`. Both variants are pre-1.0 additions.
  - **`Conductor::abort_marked_claims`.** It aborts a concurrent buffer's outstanding claims at once, whatever their deadlines, for a guard close.
  - **Unchanged for now.** The client's concurrent handle still reports a gate seal as `Closed` until the concurrent guarded handle lands (karyos#1102 part c).
