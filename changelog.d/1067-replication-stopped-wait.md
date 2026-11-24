### Fixed

- `replication_keeps_backpressure_and_fits_the_stream` no longer fails on a loaded host (karyos#1067): it waits for the recording's `Stopped` signal, at most 30 s, before it counts the messages the stop sent, instead of assuming they went out within 500 duties of 1 ms.
