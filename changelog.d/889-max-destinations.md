### Added

- `AgentConfig::max_destinations`, the most destinations of one
  multi-destination publication: 1 to 64, default 16 (MD-6;
  karyos#889). Every per-destination share of the repair tables divides
  by it (MD-8), and a publication answers `Full` past it. A value
  outside 1 to 64, or above the endpoints' `max_routes`, is refused at
  driver start with `DriverError::MaxDestinations`, and a repair table
  with less than one entry per destination with `InvalidConfig`. The
  constant `MAX_DESTINATIONS` is replaced by `DEFAULT_MAX_DESTINATIONS`
  and `MAX_MAX_DESTINATIONS`.
