### Changed

- Trace export (R-CORE-13, follow-up to the #826 review): when the page's
  first record's journal stays busy past the wait, all of that journal's
  records in the page go out `unreadable`, not only its leading run, so a
  stuck entry costs one wait per page instead of splitting pages into
  runs; the page ends at the first record of another journal left unread.
  The trade-off: those records are uncalibrated, even the ones the entry
  would have calibrated had it come free. The recycle log has its own
  1 ms wait after the table's, each part retrying its busy entries at
  least once and overrunning its wait by one yield and one read at most,
  so a stuck table entry no longer leaves the log unretried. Known limit:
  the agent remembers no stuck entry across requests (that needs the
  entry's version word in the reader API), so each request whose records
  name a journal not found while an entry is stuck waits again, about
  1 ms for each part that holds a stuck entry. `TraceMirror::hold_log`
  (karyos-sys `test-hooks`) holds a log entry mid-write.
