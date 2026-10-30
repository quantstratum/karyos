### Fixed

- The reference fixture refuses a membership change while a leadership
  handover is under way, naming the target as leader, as it already
  did for client requests (karyos#909). Before, the old leader could
  append a configuration entry the target never held, and the target's
  next term diverged from it.
