### Added

- Candidate-backed negative cases for the four membership checks with the custom core behind them: `QuorumOfVoters`, `ConfigurationNotFromLog`, `ConfigurationConflict` and `LearnerBehind` each fire against a mutant of the custom core's harness adapter, over M1, M5 and M8 with their changes asked after the election, which the unmutated adapter passes (`crates/karyos-sim/tests/membership_checks.rs`; karyos#976, karyos#1038).
