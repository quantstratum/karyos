### Changed

- The C5 harness's linearizability check holds the test service's state
  as a shared log (karyos#687): a step shares the earlier values instead
  of copying them, and the search's memo hashes a state by its length and
  digest while comparing states value by value, so a digest collision
  never makes two states equal. A W2 burst of 4,096 client sessions is
  checked in about 7 s in a release build, where the copying model took
  over 10 minutes.
