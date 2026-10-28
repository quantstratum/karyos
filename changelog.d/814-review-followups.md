### Fixed

- Follow-up to the #814 review (R-CORE-21, karyos#740): a network sender
  gate built for a lane guarded with no rate now creates its bucket from
  the first policy published to its slot (full at the new burst), so a
  rateless lane's publication getting a policy is limited at the gate too,
  not only in its handles. `LaneRefusal::Invalid` is removed: only a lane's
  reserve names a lane (`Change(ReserveCrossed)`). Freeing retired streams
  drops the freed publications' stored policies in one pass over the lanes
  left.
