### Changed

- Item 57's audit findings (karyos#777). `karyos::ConflatedBudget`
  (`karyos_sys::conflation::Budget`) is built with `Budget::new(keys,
  retries)` and is `#[non_exhaustive]`, so a later bound is not a breaking
  change; a struct literal outside its crate no longer compiles. Both
  arguments stay valid at 0, as before: `keys` 0 makes a poll a no-op,
  `retries` 0 counts as one. The facade re-exports `Overrun` and
  `SnapshotFailed` at its root beside `SnapshotSource`, so an application
  implements the trait from `karyos` alone (`Overrun` stays under
  `karyos::embedded` too), and the trait's doc states that a method added
  later comes with a default body (owner item 41).
