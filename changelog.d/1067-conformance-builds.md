### Fixed

- The karyos-ffi conformance tests no longer remove each other's build files (karyos#1067). On Linux they build `karyosd` and the admission stub (with `test-hooks`) with nested cargo runs; those ran in parallel into one shared `conformance` target directory, with two feature sets of karyos-tools. Each binary now has a target directory of its own (`conformance-karyosd`, `conformance-karyos-admission-stub`), and the nested builds run one at a time, under a process-wide mutex and an exclusive lock on `conformance.lock`, which also covers test processes sharing the target directory.
