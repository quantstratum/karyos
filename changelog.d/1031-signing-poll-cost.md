### Changed

- The running Archive's signing poll reads only the integrity journal records chained since the last poll and replays the key registry only when a key registry record is chained, instead of rereading the whole journal each second (`IntegrityJournal::records_from`). `ArchiveHandle::signing_lag` reports the coverage lag, and `karyosd` logs a warning when signed coverage falls behind `--archive-anchor-interval` and when it recovers (karyos#1031).
