### Fixed

- Close and reset follow-ups to #838 and #849 (karyos#847).
  - Each failed control close is counted: `ControlRefusal::close_failed`
    is now a count, not a flag, so `removed_close_failed` counts every
    one.
  - A control route in flight uses the data paths' grace rule: a clock
    that steps back is no time elapsed.
  - Controls waiting when the endpoint moves to a new epoch are counted
    in `waits_dropped`.
  - A plain control send drains the waiting controls first and is
    refused (`Blocked`) while one to its destination still waits, so a
    receiver never sees a control before the ANNOUNCE it refers to.
  - A removed publication's route that the full close list cannot hold
    is recorded as its endpoint's close failure, so the standing reset
    drops it; it is still counted in `removed_unrecorded`.
  - A standing reset the ring refused and then dropped counts once in
    `resets_refused`.
  - A fault while the endpoint is not active doubles the next reset
    interval only while the last reset's interval still runs.
  - The control routes' counters are checked: an overflow sets
    `overflowed` and keeps the last value.
