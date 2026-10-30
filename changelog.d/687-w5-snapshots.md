### Added

- `RaftLog::install` in karyos-cluster restarts a follower's log after a
  snapshot its snapshot store already holds verified (karyos#687, decided
  2026-10-30 by QS-COORDINATOR). Durable on return, in this order:
  1. the first-index file names the next index and the base term in one
     record;
  2. the watermark is cleared;
  3. every frame is cut;
  4. the commit becomes the base.

  `RaftLog::open_with` opens such a log only over its verified snapshot,
  and finishes an install a crash cut short. `RaftLog::open` refuses it
  with `LogError::InstallUnverified`. `RaftLog::frame_span` gives a
  frame's length from the in-memory index.
- The C5 harness's W5 snapshot half (karyos#687):
  - snapshot hooks in the core interface: `compacted`, `install` and
    `Ready::snapshot_to`, with `Unsupported` defaults scored not
    demonstrated;
  - per-server compaction every N applied entries, keeping K;
  - snapshot sends and installs, and recovery from the latest snapshot
    and the log;
  - `W5Snapshots`, which runs compaction under load, a follower held
    behind the compaction point, and crashes around an install and
    between builds.

  A case whose entries cannot fit one duty's log-read budget is refused
  before it runs.
