### Fixed

- With sealing on, a recording group whose journal directory is the Archive's own directory is refused at its start with `AgentError::GroupInArchiveDir`, naming the directory, instead of running with its journal silently unsealed (the Archive's integrity journal holds that directory's lock) (karyos#1112).
