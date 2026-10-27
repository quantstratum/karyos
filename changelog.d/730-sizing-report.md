### Added

- R-CORE-34, the sizing report (karyos#730). `karyos_driver::sizing::report`
  (Linux) computes, from a driver configuration and its streams alone, the
  bytes of every shared region the driver and its clients map, in three
  figures: configured steady state, bounded steady state (with the streams
  clients may still add, up to `max_streams`) and restart peak (with
  `max_retained_generations` predecessor mappings of every stream). Every
  line names the configuration fields it read; the report states how the
  cgroup counts a shared `memfd` page and what it excludes.
- `karyosd --sizing-report` prints that report for the other options and
  exits without starting a driver; `--dir` is not needed.

  A Linux test compares the report with the regions a driver maps, read
  from `/proc/self/maps`, to the byte; another keeps a running `karyosd`'s
  region pages within the configured figure and its resident set within
  that figure plus 10 % and 4 MiB.
