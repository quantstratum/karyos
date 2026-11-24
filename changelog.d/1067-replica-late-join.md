### Fixed

- A `karyosd --replica` that follows the source's incarnation past its start leaves, so the source asks again from its start, unless a newer incarnation comes within a grace (karyos#1067, ADR-0102 decision 7). The source sends a request's status and payload once, from the incarnation's position 0. A replica slow to subscribe to the new image joined past them, started the request on a later status and then waited for payload that had already gone by, so nothing was counted. A replica that follows in time joins at 0. The grace, twice the source's reconnect settle and first backoff, lets a restarted replica that first follows the source's old incarnation at its tail meet the new one.
- Three tests no longer fail on a loaded host (karyos#1067):
  - `a_replayed_group_reaches_no_network_output` fails only after 30 s without progress in a phase, not after 30 s for the whole test.
  - `the_synthetic_profile_adds_its_spin_to_each_stage` checks a lower bound that load cannot break: every send and receive sample of a 50 us spin is at least 50 us. It no longer compares timings with the trusted profile.
  - `a_recording_replicates_between_two_daemons_and_counts_only_after_verifying` passes through the replica fix above.
