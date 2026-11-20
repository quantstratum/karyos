### Changed

- `karyos-trace`: `TraceReport::add_subscriber` and `add_subscriber_source` take the subscriber journal's `Lane`, and a subscriber journal is expected only for messages of its lane, so a lane-0 subscriber no longer leaves a lane-1 trace `Incomplete`; single-lane reports are unchanged (karyos#992).
