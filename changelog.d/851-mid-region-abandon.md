### Fixed

- A remote client whose fetch times out after its manifest, while its
  regions are arriving, abandons that fetch with the regions still to
  come instead of leaving its session out of step (karyos#851): the
  regions that arrived are detached at once, and those that arrive later
  are drained one at a time, at the next poll or before the next fetch's
  reply, and detached. Draining at a poll never waits: it takes the fetch
  lock only if free, reads only what has arrived, and costs one load when
  nothing is abandoned.
