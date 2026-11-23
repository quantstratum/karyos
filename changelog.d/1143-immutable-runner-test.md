### Added

- A test for a privileged Linux runner (karyos#1143): with `CAP_LINUX_IMMUTABLE`, a running Archive's sealed segments cannot be opened for writing or removed, the store still reads them, and a purge releases each segment it removes before deleting it. It is ignored by default and fails, rather than skips, without the capability; `scripts/linux-test.sh` passes capabilities to its container through `KARYOS_LINUX_CAPS` (run: `KARYOS_LINUX_CAPS=LINUX_IMMUTABLE scripts/linux-test.sh -p karyos-archive --lib -- --ignored immutable_segments`).
