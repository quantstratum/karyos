### Fixed

- An unreliable lane now reports a lost tail as a local gap (karyos#806).
  When the last messages were lost and the sender went idle, only its
  heartbeat showed the tail, and the receiver ignored it: the loss was a
  silent hole, and N1 failed about one run in thirty. A fresh heartbeat
  above the covered end now opens a hole up to its position, never past
  a recorded terminal bound, and sealed as `ReorderExpired`.
- Each lost range ages from the moment it was revealed. When an open
  hole grows, through a higher heartbeat or DATA above it, the new part
  has its own detection time and its own `gap_reorder_timeout` deadline,
  and the older part keeps its own. Each part is sealed at its own
  deadline with its exact range: data of a newer part that arrives
  before its deadline is delivered, and a hole that keeps growing still
  seals its oldest part on time. Data that arrives before a part's
  deadline leaves nothing of it to seal. A reliable lane still NAKs its
  tail.
- This covers single-path publications. A redundant-path publication's
  `PATH_HB` names no position, so an unreliable redundant-path image
  still cannot see a lost tail.
