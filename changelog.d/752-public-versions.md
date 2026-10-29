### Added

- The `karyos` facade publishes its versions (R-CORE-33, karyos#752):
  `karyos::CORE_VERSION`, the core release it was built from, and
  `karyos::PROTOCOL_VERSION`, the admission protocol version its client
  announces (defined in `karyos-client`, asserted equal to the protocol's
  at compile time). They are the values the C ABI and a `libkaryos`
  package's manifest publish, readable without the C ABI, as the Python
  binding needs.
