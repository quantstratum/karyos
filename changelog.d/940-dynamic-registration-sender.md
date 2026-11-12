### Fixed

- Dynamic registration, sender side (#940; behind the refusal of dynamic
  mode on the public API): a REGISTER at the per-source or the driver's
  pending bound replaces the oldest entry it competes with instead of
  being dropped, so spoofed REGISTERs from a required receiver's address
  no longer lock it out; REGISTERs and registrants' CHALLENGEs draw on a
  per-address bucket of their own, not on `setup_answer_rate`, and an
  address the full table cannot track is bound by the driver's total;
  the first SM must name the receiver block its REGISTER named, and a
  required id holds one slot for the publication's incarnation (its
  return at another endpoint is refused, as its membership holds it
  lost); an SM refused at a held slot leaves the slot to retire at its
  timeout; a restart replaces a binding only once it is quiet for
  `destination_move_quiet`; a source in its quarantine gets no ANNOUNCE;
  a receiver restarting at its own slot is not refused for a full quota;
  a CHALLENGE whose ANSWER is refused for its rate keeps its pending
  entry; on a dynamic publication an SM adopts no binding at another
  slot's address (it could claim a required id), every optional slot
  retires with the last binding at its address whichever path removes
  it (an eviction from a full binding table left it for good), and a
  required id whose slot is held with no binding is dropped at its
  REGISTER. The new counters `dropped_quarantined`, `pending_replaced`,
  `source_rates_full`, `dropped_challenge_rate` and
  `dropped_required_lost` are not in the CnC
  yet (#942 item 9), so no user can read them.
