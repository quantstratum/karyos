### Changed

- A late multicast subscriber binds faster under loss (karyos#839,
  plan 164). An unanswered SOLICIT is retried by the receiver's duty
  after 50 ms, the wait doubling up to `setup_challenge_timeout`, for at
  most 6 SOLICITs within twice `setup_challenge_timeout` of the first;
  each retry carries a fresh nonce, and an answer to an earlier one is
  dropped and counted (`solicit_stale_answers`). A retry the RSP_SETUP
  rates refuse is not an attempt (`solicit_retries_refused`).
  Measured on Linux netem, 200 late joins: MEASUREMENTS_PENDING.
