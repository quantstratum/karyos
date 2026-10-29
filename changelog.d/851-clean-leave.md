### Changed

- The driver takes a remote client's `Leave` with a fetch outstanding (a
  fetch whose reply the client abandoned, or exports it has not detached)
  as a clean leave, not a protocol error (decided by QS-COORDINATOR,
  karyos#851): the client is no longer served, what was exported stays
  charged until its exit proof, and the new fixed counter `fetches
  abandoned at leave` counts it; `clients faulty` no longer does. This
  touches the admission code of karyos#831 (`Leave` acceptance).
