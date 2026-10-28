### Added

- Rate policy versions and run-time changes (R-CORE-21, karyos#740):
  - `EmbeddedDriver::change_rate_policy` and
    `change_aggregate_rate_policy` change a guarded stream's rate policy
    by version (compare and set). `RateAuthority::Safety` takes only a
    provable tightening (`RatePolicy::transition`); `Administrator` takes
    any valid policy. No policy goes below the stream's control reserve,
    in messages and, for a byte limit, in reserve messages of the largest
    frame (each reserved message counted as a full frame). A change on one
    lane of an aggregate of several lanes is a change of the aggregate:
    its guarded lanes, each weighed with its own policy, version and
    reserve, take it together or not at all, and each guard audits it;
    a lane's refusal is `DriverError::RateChangeOnLane`, naming the lane
    (`LaneRefusal`), with the refusal's own CnC code. An aggregate has one
    policy and one version: a lane guarded on an aggregate that has a
    policy takes it and its version, with or without a rate of its own
    (keeping its own reserve), and a lane guarded without a rate before
    the aggregate had one takes its next change. Unguarded lanes are left
    as they are. Refusals are `DriverError::RateChange` (`VersionMismatch`,
    `NotATightening`, `ReserveCrossed`, `NoRate`) and
    `DriverError::InvalidRatePolicy`, with CnC error codes 19 to 23 (23
    `RateInvalidPolicy`). A byte burst is validated against the largest
    lane MTU.
  - A change binds at once and never grants tokens: each bucket earns the
    old rates up to the change, then its level is clamped to the new
    burst (`RateLimiter::set_policy`). A byte limit added starts empty.
  - The driver publishes the policy in each bound handle's outcome ring
    (header words 6 to 12, reserved and zero in layout version 2, so no
    version change) and in the sender gate's slot
    (`karyos_sys::rate_policy_slot`, a sequence lock with a Loom model).
    A handle's copy compares the slot's sequence word on every call (one
    Acquire load) and applies a newer version before it answers; a network
    sender gate at each serve. A handle in another process now takes its
    rate copy from its ring when it binds (before, only an in-process
    handle had one), or at its first call that reads the slot whole when a
    publication was in progress at bind. A reincarnation publishes nothing
    to the gate's slot, and an aggregate's change publishes it once.
  - Every call that names a guarded stream, accepted or refused, is in
    the guard audit: outcome `RateChanged` (ring code 5), or
    `RateUnchanged` (ring code 6) for the policy in force, `before` and
    `after` the policy versions, `parameters` the authority.
