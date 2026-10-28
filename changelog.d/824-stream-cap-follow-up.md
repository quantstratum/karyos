### Fixed

- With `max_stream_bytes` set, a conflation table the driver refuses (a
  value capacity past `u32`) keeps its own `InvalidConfig` on
  `add_stream`, `add_aggregate` and a reconfiguration, instead of
  `StreamTooLarge` (karyos#824).
- A client's network publication above the cap is refused with CnC code
  24 and the lane's bytes in the detail; a C client reads them in
  `detail.value`.
