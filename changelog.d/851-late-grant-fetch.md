### Fixed

- A remote client whose fetch of a grant's regions timed out abandons that
  fetch, not its session: the manifest, arriving late, is drained at the
  next fetch (its regions closed and their exports detached), and the next
  fetch then reads its own reply. Before, the late manifest could be read
  as the next fetch's reply, which left the session out of step
  (karyos#851). A region that does not arrive still leaves the session
  out of step, now after the regions received are detached.
- The remote late-grant tests set a 50 ms timeout so that their paused
  request times out; their attach waited as little and, under load, timed
  out first. They now set the attach timeout apart; their fetches keep the
  50 ms (karyos#851, plan 166).
