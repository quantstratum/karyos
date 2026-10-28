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
  1024), and a reply stops at a whole record within 1 MiB.
  `capabilities` lists `trace-export`.
- `karyos_sys::diag_ring::scan_at_most` and
  `TraceMirrorReader::scan_at_most`: a ring scan that delivers at most a
  given number of records, so its work is bounded by that number.
