### Added

- The Archive export container writes a `Seals` section holding seal kinds 9 (offload) or 10 (restore) as section version 2 and keeps version 1 for one holding neither (ADR-0104, amending design/archive-export.md §3.2); a version 1 reader refuses version 2 explicitly, and a `Seals` section whose version does not match its kinds is refused `SealsVersion` (karyos#1113).
