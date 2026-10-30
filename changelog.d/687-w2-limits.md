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
  its nominal case, bursts at 4x the queue and the in-flight entries
  from pipelined clients (`Case::window`, each open request a session of
  its own; a client told `Busy` waits its retry interval), a follower cut
  off while the leader commits 10,000 entries, and one 4x the log-read
  limit behind. At 256 B the in-flight byte limit is never reached: every
  W2 run record states it, and the report scores it not demonstrated. The reference fixture honours every limit, as
  harness validation. A metered read is sized from the log's index (`RaftLog::frame_span`,
  new in karyos-cluster): a duty reads only whole frames that fit its
  budget, and a refused read reads nothing. W2 holds every up server to
  the same applied index and state, and every raw result line states its
  client window and what the case does not cover.
