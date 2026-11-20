### Changed

- `AgentError::ImagesOfAnEarlierRun` documents what an operator sees after a restart (the group's restart is refused and the earlier journal stays replayable) and how to continue: start the group as new in a journal of its own, in a new directory or under a new group id, with `first_group_seq` set past the earlier journal's complete prefix (karyos#1099).
