### Added

- R-CORE-34, the size of every shared region from its configuration
  (karyos#730, first part). These are the functions each region's
  constructor now uses, so they cannot drift from the size it is mapped
  with:
  - `karyos_sys::sizing::region_length`, the header stride plus the
    structure, used by `RegionRecord`;
  - `command_ring::structure_length` and `broadcast::structure_length`;
  - `counters::structure_length`, for the counters and the client
    counters;
  - `diag::{error_log, loss_report, guard_audit}_structure_length`;
  - `trace_mirror::structure_length`;
  - `LogBuffer::structure_length`.

  A Linux test creates every region kind and compares its record and its
  `memfd` size with them.
