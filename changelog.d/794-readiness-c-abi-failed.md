### Changed

- A C host that never calls `karyos_driver_startup_complete` reads
  `KARYOS_READINESS_FAILED` once `startup_timeout_ns` (30 s by default)
  has passed. Nothing else in the driver depends on it.
