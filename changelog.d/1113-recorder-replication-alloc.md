### Fixed

- A steady seal no longer allocates: `IntegrityJournal::append` checked each record against a clone of the chain's state (two maps) before writing it, four allocations per seal; it now checks in place (`ChainCheck::check`) and accepts after the write. A new test counts a steady recorder, sealing and replication cycle over the real disk and asserts it allocates nothing (karyos#1113).
