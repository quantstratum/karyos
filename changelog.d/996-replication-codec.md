### Added

- `karyos_archive::replication`: schema 6 version 1 of ADR-0091, recording replication between Archives: `ReplicateRecording`, `StopReplication`, `RecordingBytes`, `SourceSeal` (the seal record verbatim, open and closed segment kinds only) and `ReplicationStatus`, with their rules, and the source's `check_request` (requests start and end on seal boundaries) and the replica's `check_seal`. Vectors P-1 to P-6 pass byte for byte (karyos#996).
