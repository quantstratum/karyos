### Added

- `karyos_driver_options.max_stream_bytes` (ABI 0.1.5, karyos#818): the
  R-CORE-34 stream cap for a C host. 0, the default and an older caller's
  struct's, sets no cap.
  - `karyos_driver_add_stream` above the cap is `KARYOS_E_INVALID_ARGUMENT`
    with the lane's bytes in `code` and the cap in `value`.
  - A client's `karyos:udp` publication above it is `KARYOS_E_REFUSED`,
    detail code 24.
  - `karyos_driver_options` is 80 bytes.
- The conformance suite adds the feature `stream-cap` (floor ABI 0.1.5),
  with `driver.create_capped` and the scenario `op.stream.cap`; the suite
  itself still needs 0.1.3.
