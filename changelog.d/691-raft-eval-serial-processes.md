### Fixed

- The raft evaluation's real-process runs (`eval/raft-candidates/tests/real_processes.rs`, C5 v2 "Processes", karyos#691) no longer time out on macOS: they run one at a time. Every node makes each vote and append durable, and on Apple targets `StdDisk` syncs with `F_FULLFSYNC`, which flushes the whole device's cache, so libtest's six parallel runs (24 processes) waited on one another's flushes and each took about the nodes' 60 s deadline, longer than the test waited. The test now waits 75 s, past the nodes' own deadline, and a timeout reports each node's stderr.
