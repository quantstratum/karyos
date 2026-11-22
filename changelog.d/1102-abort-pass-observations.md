### Fixed

- A guard close's abort pass on a concurrent buffer (`Conductor::abort_marked_claims`, karyos#1102) aborts the claims it observes in the same call. Before, a claim the pass observed but did not abort kept a first-seen time of `u64::MAX`, so a later deadline service read the clock as going back and restarted that claim's deadline.
