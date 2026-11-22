### Fixed

- With sealing on, a group start is refused with `AgentError::GroupDirectoryUnresolved`, naming the Archive's directory, when the Archive's own directory no longer resolves (moved or removed while it runs), instead of skipping the comparison and admitting the group (karyos#1149).
