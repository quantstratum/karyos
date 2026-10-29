### Added

- A configuration file for `karyosd` (R-CORE-43, karyos#769):
  `--config <path>` reads the `[io]` table of SPEC 16.9 (TOML).
  `backend` selects the I/O backend (default `sockets`) and `require`
  the capabilities every endpoint must have active: one that lacks a
  required capability fails to open, at startup or at the first add
  that opens it.
  `[io.sockets]` sets `tx_slots`, `max_queues` and `max_routes` of each
  endpoint. `--io-backend` and `--io-require` override the file; the io
  configuration needs `--network on`.
- A backend this build does not have is refused with a typed error and
  never replaced: `io_uring` and `af_xdp` are not built,
  `ef_vi` and `dpdk` need `karyosd-native`. Any other key, table or
  name is refused by name; a table error names its key or its line.
- `karyos_tools::config`, the extension point: a backend implements
  `IoBackend` and registers in an `IoSchema`, which parses and
  validates its `[io.<name>]` table; `args::parse_with` takes the
  schema and `Options::io` gives the table back. It re-exports `serde`
  and `toml`, so a major version of either is a breaking change of
  `karyos-tools`. Running another backend waits on R-CORE-27.
- `NetworkConfig::require`: the capabilities every endpoint the driver
  opens must have active.
