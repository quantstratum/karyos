### Fixed

- A remote client whose fetch of a grant's regions timed out marks its
  session out of step, as for any message of no fetch of its own, so a
  manifest arriving late is never read as the next fetch's (karyos#851).
- The remote late-grant tests set a 50 ms timeout so that their paused
  request times out; their attach waited as little and, under load, timed
  out first. They now set the attach timeout apart; their fetches keep the
  50 ms (karyos#851, plan 166).
