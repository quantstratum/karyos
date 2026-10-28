### Fixed

- Skip policy follow-up to karyos#821 (part of karyos#834). On an
  unreliable channel a data hole's part is seen up to the heartbeat's
  mark as well as the covered end, so a tail above a data hole ages from
  when the mark showed it. The receiver feeds every lane of an image up
  to its `lane_count` to the skip policy, each mark clamped to the
  lane's terminal bound. A heartbeat tail the receive owner cannot
  compute is counted in the new `heartbeat_tail_errors` receiver counter
  instead of being dropped silently. Tests cover the parts past their
  capacity, the clamped tail seal at the driver, and both seals of a
  tail across a term end.
