### Changed

- `SegmentStore::read` keeps the last finished segment it opened and reads through that handle, instead of opening the segment's data file for every read: a catch-up scan with `RaftLog::entries` opened it twice per entry (karyos#1001). The handle is dropped before any segment file is created, cut or purged. The item 37 catch-up bench also prints the read cost per entry.
