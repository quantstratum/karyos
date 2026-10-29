### Changed

- A network endpoint's tables default to 1024 TX slots, 256 queues and
  128 routes (were 256, 64 and 64; karyos#859, plan 168): about 110
  reliable single-lane publications per endpoint instead of 24, for
  about 1.5 MiB per endpoint (1448 bytes per slot, 64 per queue and
  192 per route on Linux). Decided 2026-10-29 by QS-COORDINATOR under
  owner delegation: 24 publications per endpoint was too low for the
  core, and 1.5 MiB per endpoint is acceptable on a server. `NetworkConfig::endpoint_tables` sets them.
  The driver's own caps now bind first for single-lane publications:
  `AgentConfig::publications` (64 network publications) and
  `max_streams` (64 local streams, one per lane); an endpoint's tables
  bind first only for multi-lane ones (a four-lane reliable publication
  takes 33 slots, 30 per endpoint).
