### Added

- R-CORE-34, the sizing report (karyos#730). `karyos_driver::sizing::report`
  (Linux) computes, from a driver configuration and its streams alone, the
  bytes of every shared region the driver and its clients map, each
  rounded up to the page (`karyos_sys::ipc::page_size`), in two figures:
  - configured steady state: the regions, plus the network trace journal
    budget, listed apart as heap;
  - restart peak: configured plus `max_retained_generations` predecessor
    mappings of every declared stream, under a stated assumption (no
    reconfiguration since start).

  Streams added after start and Archive replay targets are excluded, and
  the report says why: no configuration sets their maximum geometry.
  Every line names the configuration fields it read. The report states how
  the cgroup counts a shared `memfd` page and what it excludes, and it
  refuses whatever the driver refuses.
- `DriverConfig::validate`, the check a driver applies when it is created,
  now public and shared with the sizing report.
- `karyosd --sizing-report` prints that report for the other options,
  including the Archive's two control streams with `--archive`, and exits
  without starting a driver; `--dir` is not needed.

  A Linux test compares the report with the regions a driver maps, read
  from `/proc/self/maps`, to the byte, with a conflated stream and the
  network on. Another keeps a running `karyosd`'s region pages within the
  configured figure, and its resident set within that figure plus 10 % and
  4 MiB.
