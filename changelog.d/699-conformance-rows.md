### Added

- The binding conformance suite runs its panic row (karyos#699). A
  libkaryos built for the test kit (karyos-ffi feature `test-hooks`)
  exports `karyos_test_panic_next_duty_cycle`, declared in
  `include/karyos_test_hooks.h` and never in `karyos.h`, and the new
  scenario `op.panic.poisons` (feature `fault-hook`) shows a panic on a
  driver's thread poisoning the driver, its client and that client's
  subscription and publication while a second driver and its objects
  still work, and a panic inside a caller's own `karyos_driver_do_work`
  answering `KARYOS_E_INTERNAL` instead of unwinding. `make test-hooks-absent-check`, part of pre-push,
  fails when the release library exports the hook or carries its code.
  `conformance/index.txt` rows are now scenario ids, `pending issue <N>`
  with a reason, or `outside` with a reason for a row no portable runner
  can reach; a `pending` row that names no issue is refused. The kept
  fragment pointer row is `outside`, naming its Rust test, and the older
  minor ABI row is pending on issue 700. FORMAT.md says that a
  scenario's row comes from its `covers` header, never its `feature`
  headers.
