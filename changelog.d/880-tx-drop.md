### Changed

- A sockets TX half dropped outside unwinding with pending items no
  longer panics in a debug build (karyos#880). It is counted in
  `tx_discarded_on_drop` in every build, as release builds did, and
  remains a driver bug: `reset` and `retire` are the shutdown paths.
  The default-interface multicast test shuts its nodes down on every
  skip path, so a host without a multicast route records a skip.
