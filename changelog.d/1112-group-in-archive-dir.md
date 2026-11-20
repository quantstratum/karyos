### Fixed

- With sealing on, the Archive refuses a recording group whose journal directory is the Archive's own (`AgentError::GroupInArchiveDirectory`, naming the directory), before the journal exists: that directory's integrity journal is the Archive's, so the group's journal was silently never sealed (karyos#1112).
