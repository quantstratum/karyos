### Added

- The simulation harness can inject faults into a server's driver (`DriveFault`), its service's answers and a client's reads (`Case::faults`, tests only), and the raft-rs candidate now backs `AppliedNotDurable`, `ReleasedBeforePersisted`, `DivergentResponse` and `NotLinearizable` with a real core (karyos#1038).
