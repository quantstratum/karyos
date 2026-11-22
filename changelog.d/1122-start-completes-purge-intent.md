### Added

- A test that the Archive agent's start completes a purge intent a crash left before its deletion when the intent still passes its recheck (authorised, expired, copied elsewhere): the floor moves, one integrity purge record is written and the id is free again (karyos#1122). The start's reconciliation itself came with karyos#1121.
