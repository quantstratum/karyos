### Added

- `ReplayCursor::follow`: a replay that follows a recording group as it is written. At the end of the complete prefix the consumer recovers the journal again and the cursor continues from where it stopped, without reopening, giving what a replay of the closed group gives; a gap or an incomplete event stays final (R-CORE-46, karyos#881).
