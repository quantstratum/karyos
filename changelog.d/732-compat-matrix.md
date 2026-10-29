### Added

- The wire compatibility matrix (R-CORE-36, karyos#732):
  `crates/karyos-tools/compat/matrix.toml`, indexed by the full versions
  tuple of `--versions`, not by the frame version alone, with one entry
  per ordered pair of builds and surface (admission, frame, C ABI, the
  Archive and Cluster schemas, the configuration file): interoperate,
  refuse with its typed reason, or not covered with why.
  `karyos-tools compat <FROM> <TO>` decides a pair from two `--versions`
  objects or named columns (exit 0 interoperate, 1 refuse, 2 not covered,
  3 an unreadable input), through a strict, bounded reader of the
  `karyos-versions` schema. `scripts/compat-test.sh` is the local release
  gate that runs a released tag's and this tree's builds against each
  other in Linux and compares every outcome with the matrix: 0.1.0-alpha.2
  and main refuse each other's clients at admission and interoperate
  over karyos:udp.
