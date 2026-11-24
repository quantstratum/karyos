### Added

- The C5 comparison's version 2 runs the custom core (ADR-0105) as a third variant beside `raft` and `openraft`: `Variant::InTree` (`CUSTOM`), the shared workload suite over it, version 2's W2 in-flight bytes case (8 KiB commands, 256 KiB cap) on all three cores, and a corpus runner (`eval/raft-candidates/tests/corpus.rs`) writing each core's JSON lines marked with the new `Evidence::C5Version2` (karyos#691).
