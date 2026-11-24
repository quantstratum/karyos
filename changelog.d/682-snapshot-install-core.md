### Added

- Snapshot install through the custom Raft core: a leader asks its driver for `Effects::send_snapshot` when a follower needs entries compacted away, holds it to heartbeats at the base and asks again, for the latest snapshot, when none is acknowledged within the election timeout; `Core::install` commits an installed base and acknowledges it once durable, `Core::compacted` moves the base up to a committed index, and `Core::with_snapshot` recovers over one. `Effects` gains the required `send_snapshot` (karyos#682).
