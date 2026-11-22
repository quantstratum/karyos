### Changed

- The bench smoke tests' wire child exits with a failing status and one line on standard error instead of panicking (karyos#993). The fault tests make a child fail on purpose ("receiver stopped before the sender finished"), so a passing run no longer shows a `panicked at` line that reads as a failure. The parent still judges each child by its exit status, as it does for the `karyos-bench` binary's child.
