### Fixed

- `karyos-ffi`'s conformance tests build the admission stub and `karyosd` (or bring them up to date) once per run instead of reusing whatever binary is in the target directory, so a stub of an older protocol version no longer fails `op-connect-other-version` with `protocol` (karyos#1063).
