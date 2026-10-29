### Changed

- Follow-up to the #852 review (R-CORE-21): a reincarnation's network
  sender gate starts its bucket as if empty when the reincarnation began
  (`GuardSpec::empty_since`, the time its handles' rings carry), not when
  its agent took the guard, so the gate and the handles' copies agree.
  `EmbeddedDriver::backdate_next_reincarnation` is behind the new
  karyos-driver feature `test-hooks`, never in a release build. The
  `REINCARNATED_AT` docs name what orders the word before a handle reads
  it and what a reader in another time namespace sees.
