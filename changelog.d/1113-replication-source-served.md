### Added

- The Archive's control server answers a replica's `ReplicateRecording` and `StopReplication` (schema 6, ADR-0091; karyos#1113). The agent streams the recording's sealed ranges, each range's bytes before its seal, at most the replay budget per cycle, with a status at least once a second; an unknown recording is refused with code 2 and a request off a seal boundary with code 4. A recording that stops while it replicates is reopened read only and the replication goes on to its end.
