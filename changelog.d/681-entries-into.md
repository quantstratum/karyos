### Added

- `RaftLog::entries_into` and `LogView::entries_into` read a log range into caller buffers: the entries and their payload buffers are reused in place and the read window keeps its capacity, so a second read of the same range within one segment allocates nothing (a read that crosses segments still allocates when the segment store reopens its reader file) (karyos#681, ADR-0105). The checks, errors, read window and metered budget are those of `entries`, which is now a wrapper.
