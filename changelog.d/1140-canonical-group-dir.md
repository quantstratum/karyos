### Fixed

- With sealing on, a group journal directory is compared with the Archive's own as a canonical path, so a relative path, a `..` detour or a symbolic link to the Archive's directory is refused like the directory itself, and the group's integrity journal is keyed by the canonical path; a directory that does not resolve is refused with the new `AgentError::GroupDirectoryUnresolved` (karyos#1140).
