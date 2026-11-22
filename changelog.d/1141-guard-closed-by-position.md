### Fixed

- A guard close on a concurrent guarded stream labels its aborted blocks by position (karyos#1141). Before, it labelled them by count, as the next aborted blocks the walker read, so a block its writer aborted just before the close could carry `GUARD_CLOSED` while the block the close aborted carried `WRITER_ABORTED`. Only the reason label could be wrong; no record was lost. `Conductor::aborted_positions` gives the stream positions of the blocks the last deadline service call or guard close pass aborted.
