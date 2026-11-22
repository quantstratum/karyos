### Changed

- Tests: the driver's rejoin test runs its sender on a clock the test holds and steps, so the registrant's removal is pinned to the sender's own liveness deadline from its last SM (still there one nanosecond before, gone at it) instead of a wall-clock bound with 100 ms of slack (karyos#1067).
