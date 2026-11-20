### Added

- `karyos-agent` stops cleanly on `SIGTERM` or `SIGINT`: the signal only sets a flag (`signal_hook::flag`), and the serving loop then writes the durable `agent stopped` journal record and exits 0, so the next start records no unknown interval. The stop is bounded by the new `--stop-timeout-ms` (default 5000): past it the agent exits with status 3, a second signal exits at once with status 1, and a stop record that cannot be made durable exits 1; each leaves an unclean stop. `signal-hook` is now a dependency of the `karyos-agent` package (owner item 55, karyos#710).
