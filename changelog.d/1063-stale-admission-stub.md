### Fixed

- `karyos-ffi`'s conformance tests build the admission stub and `karyosd` (or bring them up to date) once per run instead of reusing whatever binary is in the target directory, so a stub of an older protocol version no longer fails `op-connect-other-version` with `protocol` (karyos#1063).
- The head signer's tests wait until each program they write can be executed, so a concurrent test's fork no longer fails it with `ETXTBSY` (karyos#1063).
