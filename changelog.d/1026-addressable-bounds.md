### Fixed

- `SessionTable::new` checks every table's byte size against what `Vec` can address before it reserves any of them, so bounds past the address space are refused without filling the smaller tables first; on a host that overcommits memory the old order could grow a table page by page until the OOM killer stopped it (karyos#1026).
