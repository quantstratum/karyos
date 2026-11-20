### Added

- Dynamic registration tests for claims the #644 series left unpinned (karyos#943): an end to end run where a silent receiver is removed at its liveness timeout and the same receiver id registers again, the pending bound refused at the ceiling plus one, the documented `InvalidLimit { field: "required" }` of `with_required`, and drop counters asserted exactly once per REGISTER.
