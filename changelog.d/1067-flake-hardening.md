### Fixed

- Four tests no longer fail on a loaded host (karyos#1067):
  - `a_cut_header_is_refused_both_ways` and the other checkpoint tests wait for a checkpoint's end by a 120 s deadline, not by 10 000 polls of 1 ms.
  - `a_synthetic_configuration_runs_in_its_processes` checks only lower bounds: each child's sample header names the profile it ran, and every sample is at least its spin. It no longer compares its timing with a trusted run's.
  - `a_channels_linger_overrides_the_networks` uses a 1 s channel linger against the network's 60 s bound, so the margins on both sides are wide.
  - `forwarding_a_steady_replication_allocates_nothing` gives its warm-up 120 s instead of 30 s to fill a batch, and says how many messages are pending if it does not.
