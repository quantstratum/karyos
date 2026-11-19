### Changed

- A driver now refuses to start, with `InvalidConfig`, when `AgentConfig::receiver_bindings` is below `max_destinations`, for every configuration and not only one with a dynamic publication (karyos#947).
