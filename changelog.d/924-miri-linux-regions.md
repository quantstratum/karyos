### Fixed

- `make miri` on Linux: the shared region tests of `cnc_store`, `conflation`, `diag` and `trace_mirror`, which reach `memfd_create`, are excluded under Miri as the `ipc`, `mmap` and `log_buffer` region tests already were, and so are the free space test (`statvfs`) and the two-process clock test, which Miri cannot run either (karyos#924).
