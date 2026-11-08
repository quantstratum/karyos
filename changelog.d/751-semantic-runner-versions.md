### Changed

- The binding conformance suite's `FORMAT.md` states the version rule
  for a runner with no ABI version (karyos#751, decided in
  quantstratum-docs#498). Such a semantic runner checks
  `karyos::CORE_VERSION` and `karyos::PROTOCOL_VERSION` against the
  core release and protocol version it pins, before any other call;
  compares each scenario's `abi` with the ABI version its pinned core
  release declares; and answers `op.library.version` with the core
  release and protocol version, required from step B1. The release rule
  "no skip" reads "at the core release it targets" for that runner. The
  C ABI runners are unchanged.
