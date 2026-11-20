### Added

- A purge releases the immutability of each segment it removes, through the backend `Retention::set_immutability` sets, only after every retention check passed and right before the deletion; a failed release deletes nothing. `CopyCatalog::record_enforced` records a sealed segment's copy with the enforcement its backend applied, and `SegmentStore::segment_files_below` names the segments a purge removes (karyos#995).
