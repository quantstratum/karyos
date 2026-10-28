### Added

- R-CORE-35 over the C ABI (karyos#794), ABI 0.1.3:
  - `karyos_driver_startup_complete(driver, *complete)` declares the host's
    startup complete. It writes 1, or 0 when `startup_timeout_ns` had
    already passed.
  - `karyos_driver_readiness(driver, *out)` writes a `karyos_readiness`:
    the state (`KARYOS_READINESS_STARTING`, `_READY`, `_RECOVERING`,
    `_NOT_READY`, `_FAILED`), the reason (`KARYOS_READINESS_REASON_*`),
    and the uptime. The values are those of the admission protocol's
    readiness probe. A `size` below 24 bytes is
    `KARYOS_E_INVALID_ARGUMENT`; a larger one gets the fields this version
    knows.
  - `karyos_driver_options` gains `startup_timeout_ns`. Its default is 30 s,
    and an older caller's struct gets that default; 0 is refused.
  - Both calls work with or without `karyos_driver_start`.
- `EmbeddedDriver::uptime` is public on every platform, and
  `Readiness::wire` gives the probe's state and reason codes. The admission
  server's probe answer and the C ABI share them.
- The conformance suite needs ABI 0.1.3. It adds `driver.readiness.invoker`,
  `driver.readiness.threaded` and `struct.size.readiness`.
