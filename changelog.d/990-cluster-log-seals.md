### Added

- The Cluster log seals its committed bytes through an integrity journal in its directory, never past the commit's entry, and an install starts a new seal subject before it cuts. At a takeover, a log recovered below its seals is refused with `LogError::ShortenedBelowSeal`, naming the lost range, before anything is written (karyos#990).
