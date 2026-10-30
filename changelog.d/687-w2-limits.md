### Added

- The C5 harness declares W2's limits to the core under test
  (karyos#687). `ConsensusCore::recover_with` takes `Limits`: in-flight
  entries and bytes per follower, a request queue per server, and log
  bytes read per duty. A core that takes none answers `Unsupported`, and
  its W2 cases are reported as `not_demonstrated`, never as passed.
  `propose` refuses with `Refused::NotLeader` or a typed
  `Refused::Backpressure(Limit)`; each backpressure refusal is recorded,
  and the client sends again, so nothing is lost. The harness holds a
  core's log reads to its per-duty budget (`ReadError::Budget`). W2 runs
  its nominal case and a follower cut off while the leader commits
  10,000 entries, then catching up; the bursts at 4x each limit wait for
  pipelined clients. The reference fixture honours every limit, as
  harness validation.
