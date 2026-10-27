### Added

- `karyos-feed` A/B arbitration (`quantstratum-docs:
  karyos/design/feed-arbitration.md`; SPEC §7.2; karyos#659). An `Arbiter`
  over a feed's `FeedSequencer` (epoch, sequence, modulus, epoch start)
  delivers each sequenced message of lines A and B once, in order, from the
  line that brought it first. A message missing on one line is repaired
  from the other; one missing on both is a `Gap` once both lines passed it,
  its skew window expired or the reorder buffer overflowed. A session reset
  is an epoch change the feed states; a wrap is serial arithmetic inside a
  window strictly below half the space, and a message at or beyond it is a
  `Jump`. At a reset the old epoch's holes stay open while the lagging
  line can still repair them, the new epoch's messages waiting under their
  own base; old epoch messages after the close are dropped. `resync`
  resumes a snapshot's consumer after a stated position. Named counters
  cover wins, duplicates, late copies, length conflicts and the rest. The reorder buffer is allocated at construction:
  a steady cycle allocates nothing.
