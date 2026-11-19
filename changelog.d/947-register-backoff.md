### Changed

- A driver now refuses to start, with `InvalidConfig`, when `AgentConfig::receiver_bindings` is below `max_destinations`, for every configuration and not only one with a dynamic publication; an embedder that raised `max_destinations` above 64 raises `receiver_bindings` with it. A dynamic subscription's REGISTER backoff is no longer reset by an ANNOUNCE, only by an accepted ANSWER or a bound image, so a receiver its sender cannot bind registers at most every 1.6 s (karyos#947).
