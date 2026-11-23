### Fixed

- Three tests no longer fail on a loaded host (karyos#1067):
  - `a_cut_header_is_refused_both_ways` and the other checkpoint tests wait for a checkpoint's end by a 120 s deadline, not by 10 000 polls of 1 ms.
  - `a_synthetic_configuration_runs_in_its_processes` checks bounds that load cannot break: every synthetic sample is at least its spin, and the trusted run's fastest sample is below it. Before, it compared two medians.
  - `a_channels_linger_overrides_the_networks` uses a 1 s channel linger against the network's 60 s bound, so the margins on both sides are wide.
