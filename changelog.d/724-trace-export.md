### Added

- Raw trace export (R-CORE-13, karyos#724). The new API v1 request
  `KARYOS-AGENT 1 trace-export DIR FROM [COUNT [EPOCH]]` returns pages of
  the attached driver's trace mirror records, read from the mirror at the
  call: whole records in mirror sequence order, `next` to resume from,
  the ring's `head`, and the journals the records name as the table showed
  them (entry with clock provenance, time namespace and drop ranges;
  recycle log entry; or unknown). The epoch is the driver instance (32 hex
  digits): a cursor survives the collector's and the agent's restart, and
  one of another instance gets the typed `epoch changed` refusal with the
  new epoch. A cursor behind retention, or a record overwritten during the
  read, is never refused or delivered torn: the page states the lost
  sequences first, in `lost`. At most 16 384 records per request (default
  1024). A reply holds whole records, each counted with its journal the
  first time one names it, within 1 MiB plus one record and one journal
  (`MAX_RECORD_REPLY`, 695 bytes; `MAX_JOURNAL_REPLY`, 2560 bytes), the
  read itself bounded by those bytes and the count clamped to 16 384; it
  names only the journals of the records it holds. A cursor beyond the
  ring is refused (`cursor ahead`, with the ring's `next`), as is a read
  that finds the ring's bounds busy (`mirror busy`); the head is always
  the ring's. A record whose journal entry stays busy ends the page
  before it (the reader retries); a journal recycled for good goes out as
  `unknown`, its records counted in `unknown_records`. A malformed record
  (a length past the payload bound, `MirrorRecord::truncated`) is never
  delivered: it is lost with its sequence and reason `malformed`, and the
  page goes on. A table or log entry being written is retried, yielding,
  for 1 ms, the table's before the log is read, as the driver writes a
  log entry before it reuses a table entry; one still busy then, while a
  page's first record is its journal's, never stalls the cursor and loses
  nothing: that journal's leading run of records goes out without
  calibration, its journal `unreadable`, counted in `unreadable_records`,
  and the page ends at the next record whose journal was not read. Each lost range carries its `reason`
  (`overwritten` or `malformed`), is stated once, and is below the page's
  `next`. The read alone bounds the page, in
  batches of 64 records; `json::trace_export` encodes it whole.
  `capabilities` lists `trace-export`.
- `karyos_sys::diag_ring::scan_at_most` and
  `TraceMirrorReader::scan_at_most`: a ring scan that delivers at most a
  given number of records, so its work is bounded by that number.
- `trace-buckets` paging (R-CORE-23, review of karyos#817): a bucket's
  `loss` is on its first page only (`first_lane` 0) and `null` on a later
  page of it, so a reader never counts it twice; no page holds a bucket's
  header without a lane.
- The API socket writes each reply within `WRITE_DEADLINE` (250 ms) in
  all, checked after every write: a reply a client reads too slowly is
  cut short, and the connection closed, so it ends at EOF without its
  final newline; a reply written whole is served even if its last write
  ended at the deadline. `limits` answers it as `write.deadline_ms`. A
  request is read within `READ_DEADLINE` (250 ms) in all, each read under
  the time left (`read.deadline_ms`). One poll
  starts connections for `POLL_BUDGET` (500 ms) at most, so its waiting on
  clients is 1 s at most, besides the work of building the answers. Refusals of
  `trace-export` are served as refusals.
