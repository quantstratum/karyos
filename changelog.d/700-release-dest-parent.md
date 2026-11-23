### Fixed

- `scripts/release-libkaryos.sh` creates its DEST's parent before moving the artifacts there, so a run with `CARGO_TARGET_DIR` outside the tree (no `target/`) no longer fails at the end; found building the 0.1.0-alpha.4 Linux artifacts in Docker (karyos#700).
