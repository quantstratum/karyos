### Changed

- The Raft log seals its committed bytes in whole `SEAL_CHUNK`s (1 MiB) instead of at every commit advance, so the integrity journal holds one record per chunk of committed log and an open replays that many, not one per commit advance; the commit path no longer pays a journal fsync per advance. Up to one chunk of committed tail stays unsealed between seals: `RaftLog::seal` seals it (a clean close), and a purge seals it before removing anything. The takeover check still refuses a log recovered below its seals (karyos#1050).
