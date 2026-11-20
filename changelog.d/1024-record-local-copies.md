### Added

- With `AgentConfig::copy_location`, the running Archive records each recording that closes sealed as a verified local copy in the copy catalog. Each segment file is made immutable through the platform backend (the immutable attribute on Linux), and the copy records the enforcement that applies, the digest of its seals, and this Archive's location. `SegmentStore::segment_files` lists a recording's segment files (karyos#1024).
