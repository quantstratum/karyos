### Fixed

- The remote reincarnation rate test ran at a thousand messages a second,
  so a bind delayed 2 ms under load already earned the burst it expected
  to be empty; it runs at ten a second now, with a 250 ms backdate for the
  burst case. The images-in-turn test states why its witness subscription
  proves the other's images hold their messages (karyos#856 review).
