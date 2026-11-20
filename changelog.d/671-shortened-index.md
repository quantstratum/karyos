### Fixed

- An index shortened by media damage no longer drops sealed events silently at an Archive restart (u5; part of karyos#671): with sealing on, the agent compares each recording a crash left open, as A2's recovery kept it, with what its seals cover. One recovered below its seals is reported as `Event::IndexShortened` with the lost range and the first seal it breaks, and is counted by `ArchiveHandle::shortened_indexes`. An unindexed tail above the last seal is still an unacknowledged write. `integrity::damage::shortened_below_seal` is the check.
