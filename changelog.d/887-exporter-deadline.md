### Changed

- `karyos-exporter`'s connection deadline is 2 s by default over TLS, which fits a remote scrape of about 100 KiB at round trips up to 300 ms, and stays 250 ms on plain loopback; `--deadline-ms` (1 to 30000) sets it, and a poll takes no further connection once it has run for the deadline (karyos#887 review).
