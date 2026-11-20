### Changed

- CRC-32C runs slicing by 8 (eight bytes a step through eight tables) instead of a byte at a time, in safe code and without a dependency: every segment write and read, the snapshot store and the log's frame check get faster per byte (karyos#1045).
