### Fixed

- Dynamic registration, sender side (#940; behind the refusal of dynamic
  mode on the public API): a REGISTER at the per-source or the driver's
  pending bound replaces the oldest entry it competes with instead of
  being dropped, so spoofed REGISTERs from a required receiver's address
  no longer lock it out; REGISTERs draw on a per-address bucket of their
  own, not on `setup_answer_rate`; the first SM must name the receiver
  block its REGISTER named, and a required id holds at most one slot; a
  restart replaces a binding only once it is quiet for
  `destination_move_quiet`; a source in its quarantine gets no ANNOUNCE;
  a receiver restarting at its own slot is not refused for a full quota;
  a CHALLENGE whose ANSWER is refused for its rate keeps its pending
  entry. New counters `dropped_quarantined` and `pending_replaced`.
