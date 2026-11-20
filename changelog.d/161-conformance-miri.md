### Fixed

- `make miri` no longer aborts in `karyos-ffi`'s conformance tests (karyos#161): `the_runner_keeps_its_karyosd_client_served_between_scenarios` reads the suite's files, which Miri's isolation forbids. It is now ignored under Miri, as the conformance tests beside it are.
- `make miri` runs in three parts, `miri-sys-log-buffer`, `miri-sys-rest` and `miri-ffi`, and CI runs each as its own job with a 6 h limit (karyos#161). The full run took about 10 h on a shared Linux host, beyond one job's limit.
