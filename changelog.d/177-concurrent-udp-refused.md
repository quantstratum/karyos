### Changed

- A C ABI test shows that a driver with its network refuses a concurrent publication on a `karyos:udp` channel with `KARYOS_E_UNSUPPORTED_CHANNEL`, writing no handle. ADR-0099 keeps timed lanes exclusive on this refusal (karyos#177). The Rust facade's case was already covered.
