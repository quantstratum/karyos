### Fixed

- A redundant-path publication's idle lane now sends the idle DATA
  heartbeat on every path that can send (karyos#834), as a single-path
  lane does on its one. Each path waits a whole interval after its own
  last DATA or heartbeat, and while a path holds copies of the lane (its
  socket full, or its endpoint in a reset) every path's heartbeat stops
  at that path's frontier: it never announces a position a held copy
  would still bring, and still reveals a tail lost below it; PATH_HB still keeps each path's binding live
  (RP-3). A tail lost on every path is now revealed: a reliable image
  NAKs it, and an unreliable one seals it as a local gap at the reorder
  deadline, with its exact range. A tail lost on one path still arrives
  by the other. The cost while idle is one 32-byte frame per lane per
  path per `sender_heartbeat_interval`: N lanes over P paths send N × P
  frames each interval.
