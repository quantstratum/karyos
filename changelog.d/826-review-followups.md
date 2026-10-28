### Changed

- Trace export (R-CORE-13, follow-up to the #826 review): when the page's
  first record's journal stays busy past the wait, all of that journal's
  records in the page go out `unreadable`, not only its leading run, so a
  stuck entry costs one wait per page instead of splitting pages into
  runs; the page ends at the first record of another journal left unread.
  The recycle log has its own 1 ms wait after the table's (2 ms in all at
  most, plus one yield), so a stuck table entry no longer leaves the log
  unretried. `TraceMirror::hold_log` (karyos-sys `test-hooks`) holds a
  log entry mid-write.
