### Added

- The frozen W1 workload on 3 and 5 real processes for every Raft variant (raft-rs, OpenRaft, the custom core): servers serve the harness test service over C4's log, one `raft-eval-client` process per client session runs the harness client, and the merged, monotonic-clock-stamped observations and histories pass through `workloads::pass`; `workloads::outcome` and a public `workloads::script` in `karyos-sim` (C5 v2, "Processes"; karyos#691).
