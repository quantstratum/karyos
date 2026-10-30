### Added

- Read leases on committed term bytes (karyos#771, R-CORE-45 part 1).
  `LogBuffer::install_leases` installs a bounded bank of lease words, on
  the creating process's buffer only (an attached one is refused,
  `SysError::LeasesNotOnAttached`). `SenderRead::lease_committed`
  validates the frames a copy would carry and leaves them in the term
  under a `ReadLease` instead of copying them. While a lease lives,
  reclaim keeps its slot quarantined, so the term is never cleaned or
  reused under it, across any rotation. Dropping the lease ends it with
  one `Release` store, from any thread, with no lock and no allocation.
  `ReadLease::copy_to` stages a lease byte for byte as `read_committed`
  copies. A full bank, a padding or aborted record at the cursor, or a
  reader that borrows its buffer (`&LogBuffer`) stages
  (`LeaseOutcome::Stage`), with the cursor unmoved. `ReadLease` names no
  buffer type: it holds its `Arc`-owned buffer as a trait object, with
  no allocation, so a backend can keep leases of any buffer. `TermBytes`
  is now `'static`. New counters: `leases`, `lease_bytes`,
  `leases_staged`. The `loom_read_lease` models check that cleaning
  never races a lease released on another thread, with a second lease
  taken concurrently on the same term.
