### Added

- `make libkaryos-release-check` builds the two release artifacts, `libkaryos` without `karyosd` and `karyosd` alone, from a clean tree with their `SHA256SUMS`, and runs the conformance suite against the `libkaryos` archive itself; a CI job runs it on x86_64 and aarch64 Linux. Nothing is signed or published: that stays the release key custodian's step (part of karyos#700).
