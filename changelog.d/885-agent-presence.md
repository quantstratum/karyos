### Changed

- The agent's join registry observes `stream` entries (karyos#885):
  `present`, `holders` and `shared` count the publications of every
  lane whose `stream wire id` cell names the entry's key, a client's
  `publication` cell each plus the lane's `embedded publications`. They
  stay `null` while the driver is not attached, before its first
  positions pass, and while `counters unavailable` is nonzero, so a
  shared stream is never shown unshared; a count that would overflow
  is unknown too.
