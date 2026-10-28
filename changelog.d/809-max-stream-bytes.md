### Added

- R-CORE-34 follow-up (karyos#809): `DriverConfig::max_stream_bytes`.
  - It is the most bytes one stream lane may take: its log buffer region
    plus its conflation table's, by `karyos_driver::stream_lane_bytes`
    (new, public).
  - Every lane the driver makes is checked against it: `add_stream`,
    `add_aggregate`, network publications, replay targets, a guard
    reincarnation and a reconfiguration's successor.
  - A larger one is refused with the new `DriverError::StreamTooLarge`,
    and nothing is created.
  - `None`, the default, bounds nothing; `Some(0)` is refused.
- With the cap set, the sizing report adds two figures that need no
  assumption, and no longer excludes added streams. A declared stream
  above the cap is refused.
  - Bounded steady state: the regions that are not streams, the heap
    budgets, and `max_streams` lanes at the cap.
  - Bounded restart peak: bounded plus every lane's retained generations
    at the cap.
- `karyosd --max-stream-bytes <size>`. It rejects 0.
- `LogBuffer::<SharedTerms>::structure_length` and
  `ConflationConfig::structure_length` are available on every platform.
