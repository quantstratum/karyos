### Fixed

- Rate policies at a reincarnation (R-CORE-21, follow-up to the #841
  review): a handle bound to a reincarnation of its publication (an
  incarnation past the first), in process or remote, starts its rate copy
  empty at the time the reincarnation began and has earned since, as the
  reincarnation's sender gate has: reincarnating buys no new burst, and a
  handle bound later is not stricter than the gate
  (`GuardBinding::reincarnated_at`, decided by QS-COORDINATOR). The driver
  writes that time, host monotonic nanoseconds, in header word 13 of each
  handle's outcome ring (`outcome_ring::REINCARNATED_AT`, reserved and zero
  before, so no layout change); a handle that reads 0 (the first
  incarnation, or a driver that predates the word) starts empty.
