### Changed

- `RaftLog::entries` reads frames the index places back to back in windows of up to 1 MiB instead of two reads per entry, still checking every frame: reading 1 GiB of 256 B entries back for catch-up drops from 0.68 to 0.14 µs per entry on an unloaded host (karyos#1001).
