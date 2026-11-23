### Added

- The simulation harness catches a core's panic at its core boundary, whatever the core, records it (`Observation::CorePanicked`) and stops that server instead of aborting the run, so the checks see what came before; `Violation::CorePanicked` is reported only when no other check names a cause. Under `test-hooks`, `SimDisk::lying_about_syncs` acknowledges file syncs without making them durable. The raft-rs candidate now backs `DurableLost` and `CommittedTruncated` (karyos#976, karyos#1038).
