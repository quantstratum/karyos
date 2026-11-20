### Added

- A byte budget for the session table: `SessionTable::new_within` and `ContainerConfig::session_budget` (default `dedup::DEFAULT_BUDGET`, 2 GiB, room for the large profile) refuse bounds whose reserved bytes pass it with `ConfigError::OverBudget`, for the container's own bounds and for bounds a log entry carries, before anything is reserved. No bounds can drive a replica, or a test host, into memory exhaustion on any operating system (karyos#1070).
