### Added

- The channel URI key `retransmit-window=<bytes>` (karyos#653, owner
  item 63) sets a reliable UDP publication's repair window per channel,
  fixed at channel creation. The value must be positive and a multiple
  of 32, and at most half the term; the default is half the term. The URI
  refuses a value that is zero, unaligned, above half of a `term-length`
  it gives, or combined with `reliable=false` (a `Conflict`). The driver
  refuses a value above half of the stream's term with
  `DriverError::RetransmitWindowAboveHalfTerm` before anything is
  configured. Without the key, the driver's `RepairConfig` applies. The
  held floor without required receivers is `sent` minus the window, and
  a test shows that a small window makes the lone counted receiver's
  hole unrecoverable, reported as such. `CHANNEL-URI.md` lists the key.
