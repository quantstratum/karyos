### Fixed

- karyos-ffi's tests give their client conductors an hour's driver timeout under Miri, as karyos-sim's and karyos-driver's do: under the interpreter the embedded driver's heartbeat could stall past the 10 s default, the client gave the driver up as lost and a pending add failed as `KARYOS_E_UNKNOWN` (karyos#1117). `tests/connect.rs` and `tests/outcomes.rs`, the cross-process client's tests, are compiled out under Miri, as MIRI.md already states they run natively only.
