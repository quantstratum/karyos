### Added

- An embedded driver's network over the C ABI (karyos#735), ABI 0.1.4.
  - `karyos_driver_options` gains `network` (`KARYOS_NETWORK_OFF` 0 or
    `KARYOS_NETWORK_ON` 1) and `reserved0`.
  - ON runs the driver's network agents with their default configuration,
    on their own threads, so its clients create `karyos:udp` publications
    and subscriptions with the existing calls.
  - An older caller's struct, and OFF, keep the IPC-only driver.
  - Any other value, or a nonzero `reserved0`, is
    `KARYOS_E_INVALID_ARGUMENT`, with nothing created.
  - Only on and off are exposed. The rest of the network configuration
    keeps its defaults, as with `karyosd --network on`, and the header
    lists it.
- The conformance suite needs ABI 0.1.4. It adds the feature
  `embedded-network`, with `driver.create_networked` and `$network_uri`,
  and the scenario `op.embedded.network`.
