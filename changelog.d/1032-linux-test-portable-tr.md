### Fixed

- `scripts/linux-test.sh` now runs on hosts whose `tr` is uutils coreutils (Ubuntu 25.10 and later; karyos#1032): the character set that names the tree ends with `-`, so `.-\n` is no longer read as a reversed range.
