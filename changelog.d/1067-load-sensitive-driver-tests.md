### Changed

- Tests: the driver's rejoin test runs its sender's network clock (the agents' duty time, a test-only `Network::set_clock`; the driver's injected clock times claim deadlines only) on a clock the test holds and steps, so the registrant's removal is pinned to the sender's own liveness deadline from its last SM (still there one nanosecond before, gone at it) instead of a wall-clock bound with 100 ms of slack (karyos#1067).
- Tests: the replayed SETUP test counts each replay's drop as it is handled, instead of an exact total over the run that other control frames from the rig's real sockets could raise under host load (karyos#1067).
