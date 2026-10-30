### Changed

- The agent's join registry follow-ups (karyos#893). A `join-list`
  cursor is checked as a key, as `join-get` checks one: a malformed or
  oversized cursor is refused. The registry's version number,
  `history_dropped` and `evicted` counters refuse a put that would pass
  `u64::MAX` with `{"error":"counter overflow"}`, and a refused put
  changes nothing (SPEC §14). `join.memory_bytes` is now a true bound,
  7 208 960 bytes: the counting allocator measures a registry filled to
  every bound at 7 057 552 bytes held, which the earlier 6 864 896 did
  not cover. Property tests cover the join request parser, the
  registry's bounds and the exporter's token check. The exporter answers 400 to a head with a header line that is not
  UTF-8, instead of reading only the headers before it, where an earlier
  `Authorization` could have been taken for the last one.
