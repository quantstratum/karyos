### Added

- `RaftLog::set_archive_hold` takes the Archive's hold state on the log's recording, and while it is held, pending or unknown, `purge_prefix` and `install` are refused with the typed `LogError::ArchiveHeld`, changing nothing: snapshot install and compaction never purge through an Archive hold (karyos#682). Crash tests over every disk operation of a follower's install and of a compaction through the custom core (`install_crash.rs`) check the replica is rebuilt, consistent and retries an unfinished install.
