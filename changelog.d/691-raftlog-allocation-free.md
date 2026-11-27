### Changed

- The Cluster log allocates nothing per entry on its hot path (karyos#691). Each entry is framed into a buffer the log keeps (`Entry::frame_into`). The hard state is replaced through paths built once, with the same crash-safe steps. `RaftLog::reserve` sizes the entry index ahead. Once warm, an append, a sync and a hard state save on `StdDisk` make no allocation and no free, where they made 2.76 allocations and 2.00 frees per entry before.
