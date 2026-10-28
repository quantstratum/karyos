### Added

- R-CORE-34 follow-up (karyos#809): `DriverConfig::max_stream_bytes`.
  - It is the most bytes one stream lane may take: its log buffer region
    plus its conflation table's, by `karyos_driver::stream_lane_bytes`
    (new, public).
  - Every lane the driver makes is checked against it: `add_stream`,
    `add_aggregate`, network publications, replay targets and a
    reconfiguration's successor. A guard reincarnation keeps its stream's
    geometry, so it stays within the cap.
  - A larger one is refused with the new `DriverError::StreamTooLarge`,
    and nothing is created.
  - A configuration a buffer or a table refuses keeps its own error,
    whether the cap is set or not.
  - A C host's `karyos_driver_add_stream` gets
    `KARYOS_E_INVALID_ARGUMENT`, with the lane's bytes and the cap in the
    detail.
  - A client's network publication above the cap is refused with the new
    wire code `StreamTooLarge` (24); a C client gets `KARYOS_E_REFUSED`,
    detail code 24.
  - `None`, the default, bounds nothing; `Some(0)` is refused.
- With the cap set, the sizing report adds two bounded figures and no
  longer excludes added streams, replay targets or network publications
  (`EXCLUDED_CAPPED`). A declared stream above the cap is refused.
  Without it, the report is unchanged.
  - The bounded figures assume no incarnation a guard close replaced is
    still retiring (`BOUNDED_ASSUMPTION`), and the report says so.
  - Bounded steady state: the regions that are not streams, the heap
    budgets, and `max_streams` lanes at the cap.
  - Bounded restart peak: bounded plus every lane's retained generations
    at the cap.
- `karyosd --max-stream-bytes <size>`. It rejects 0.
- `LogBuffer::<SharedTerms>::structure_length` and
  `ConflationConfig::structure_length` are available on every platform.
