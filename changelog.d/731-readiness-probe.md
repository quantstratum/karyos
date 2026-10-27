### Added

- R-CORE-35, a bounded startup and readiness signal for a driver
  (karyos#731).
  - `EmbeddedDriver::readiness` reports one of five states: starting,
    ready, recovering (a stream retains a cutover's predecessor), not
    ready (orderly shutdown, full or terminal) or failed (startup
    deadline). It is derived from the conditions a client `Hello` is
    admitted under.
  - `EmbeddedDriver::startup_complete` and `DriverConfig::startup_timeout`
    (30 s) bound startup. A host that never declares its startup complete
    reports failed. `karyosd` declares it once its streams and Archive
    exist.
  - The admission protocol (version 3) gains `ProbeHello` and `ProbeState`.
    A probe gets no descriptor or slot, does not count against
    `max_clients` or `max_tools`, and one step answers at most
    `MAX_PROBES_PER_STEP` (4) probes.
  - Linux: `karyos_client::probe::probe` and `karyos-tools probe --dir D`.
    The command exits 0 ready, 1 starting or recovering, 2 not ready or
    failed, 3 unreachable, 4 incompatible driver and 5 refused.
