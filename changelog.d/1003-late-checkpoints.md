### Added

- Live replay delivers a checkpoint a writer recorded for an event a follower had already given, without the prefix advancing: `Recovery::checkpoints` lets a poll discover it, and `ReplayCursor::follow` then gives it as `Step::LateCheckpoint`, before any later event (karyos#1003).
