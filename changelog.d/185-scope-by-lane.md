### Changed

- `TraceReport::out_of_scope` takes the lane a declaration applies to (`None` for every lane), and `karyos-trace` scopes a recycled journal's boundary to that journal's own lane, so a multi-lane aggregate's other lanes stay in scope (karyos#185).
