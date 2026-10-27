### Added

- The netem suite isolates each fault (karyos#626). N10 and N11 run
  under reorder alone, with a probe that fails unless the path reordered
  and lost and duplicated nothing: a reliable channel still delivers
  exactly once and in order, and an unreliable one at most once and in
  order, every datagram too late for its place in a reported local gap.
  N3 adds a duplicates-only phase, in which nothing is NAKed or repaired
  and every DATA frame dropped is a duplicate. N4 asserts the repair in
  Dedicated mode through the per-stream cells. `RELEASING.md`: a release
  is not tagged until every gate has an Evidence row for its own head.
