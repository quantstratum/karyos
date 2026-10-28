### Added

- Rate policy versions and run-time changes (R-CORE-21, karyos#740):
  - `EmbeddedDriver::change_rate_policy` and
    `change_aggregate_rate_policy` change a guarded stream's rate policy
    by version (compare and set). `RateAuthority::Safety` takes only a
    provable tightening (`RatePolicy::transition`); `Administrator` takes
    any valid policy. No policy goes below the stream's control reserve.
    Refusals are `DriverError::RateChange` (`VersionMismatch`,
    `NotATightening`, `ReserveCrossed`, `NoRate`), with CnC error codes
    19 to 22.
  - A change binds at once and never grants tokens: each bucket earns the
    old rates up to the change, then its level is clamped to the new
    burst (`RateLimiter::set_policy`). A byte limit added starts empty.
  - The driver publishes the policy in each bound handle's outcome ring
    (header words 6 to 12, reserved and zero in layout version 2, so no
    version change) and in the sender gate's slot
    (`karyos_sys::rate_policy_slot`, a sequence lock with a Loom model).
    A handle's copy reads it on its slow path; a network sender gate at
    each serve. A handle in another process now takes its rate copy from
    its ring when it binds (before, only an in-process handle had one).
  - Every change, accepted or refused, is in the guard audit: outcome
    `RateChanged` (ring code 5), `before` and `after` the policy
    versions, `parameters` the authority.
