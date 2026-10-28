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
  (`MAX_RECORD_REPLY`, 695 bytes; `MAX_JOURNAL_REPLY`, 2304 bytes); it
  names only the journals of the records it holds.
  `capabilities` lists `trace-export`.
- `karyos_sys::diag_ring::scan_at_most` and
  `TraceMirrorReader::scan_at_most`: a ring scan that delivers at most a
  given number of records, so its work is bounded by that number.
- `trace-buckets` paging (R-CORE-23, review of karyos#817): a bucket's
  `loss` is on its first page only (`first_lane` 0) and `null` on a later
  page of it, so a reader never counts it twice; no page holds a bucket's
  header without a lane.
- The API socket writes each reply within `WRITE_DEADLINE` (250 ms) in
  all, in 64 KiB writes: a reply a client reads too slowly is cut short,
  without its final newline, never holding the polling thread longer.
  `limits` answers it as `write.deadline_ms`.
