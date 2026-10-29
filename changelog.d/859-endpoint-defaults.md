### Changed

- A network endpoint's tables default to 1024 TX slots, 256 queues and
  128 routes (were 256, 64 and 64; karyos#859, plan 168): about 110
  reliable single-lane publications per endpoint instead of 24, for
  about 1.4 MiB of TX pool per endpoint (1448 bytes per slot). Decided
  2026-10-29 by QS-COORDINATOR under owner delegation: 24 publications
  per endpoint was too low for the core, and 1.4 MiB per endpoint is
  acceptable on a server. `NetworkConfig::endpoint_tables` sets them.
