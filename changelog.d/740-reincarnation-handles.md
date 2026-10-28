### Fixed

- Rate policies at a reincarnation (R-CORE-21, follow-up to the #841
  review): a handle bound to a reincarnation of its publication (an
  incarnation past the first), in process or remote, starts its rate copy
  empty, as the reincarnation's sender gate does, so the two agree and
  reincarnating buys no new burst (`GuardBinding::reincarnated`).
