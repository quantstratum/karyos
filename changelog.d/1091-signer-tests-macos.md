### Fixed

- `karyosd`'s head signer test of a descendant outside the signer's process group runs on Linux only, where the output read is cancellable; elsewhere the read blocks by design, so the test failed `make pre-push` on macOS (karyos#1091). Off Linux, a signing program reaped by `try_wait` is no longer signalled through its process group afterwards, whose id may have been reused (karyos#1084).
