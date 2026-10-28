### Fixed

- An unreliable lane now reports a lost tail as a local gap (karyos#806).
  When the last messages were lost and the sender went idle, only its
  heartbeat showed the tail, and the receiver ignored it: the loss was a
  silent hole, and N1 failed about one run in thirty. A fresh heartbeat
  above the covered end now opens a hole up to its position, never below
  the image's join point, sealed as `ReorderExpired` at the same reorder
  deadline as any other hole. Data that arrives before the deadline
  leaves nothing to seal. A reliable lane still NAKs its tail.
