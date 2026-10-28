### Fixed

- A redundant-path publication's idle lane now sends the idle DATA
  heartbeat on every path that can send (karyos#834), as a single-path
  lane does on its one. Each path waits a whole interval after its own
  last DATA or heartbeat, and while any path holds a copy of the lane (its
  socket full, or returning to the live set; a path that left with its
  endpoint's half away bounds nothing, as it sends nothing) every path's heartbeat stops at that copy's
  position: it never announces a position a held copy would still bring,
  and still reveals a tail lost below it. A tail above a copy held for
  long is revealed once the copy goes. PATH_HB still keeps each path's
  binding live (RP-3). A tail lost on every path is now revealed: a reliable image
  NAKs it, and an unreliable one seals it as a local gap at the reorder
  deadline, with its exact range. A tail lost on one path still arrives
  by the other. The cost while idle is one 32-byte frame per lane per
  path per `sender_heartbeat_interval`: N lanes over P paths send N × P
  frames each interval.
