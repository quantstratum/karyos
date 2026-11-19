### Fixed

- `make miri` on Linux: the shared region tests of `cnc_store`, `conflation`, `diag` and `trace_mirror`, which reach `memfd_create`, are excluded under Miri as the `ipc`, `mmap` and `log_buffer` region tests already were (karyos#924).
