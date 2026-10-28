### Fixed

- The IPC descriptor count test no longer fails intermittently
  (karyos#804). It counted the driver process's descriptors after the
  warm-up client exited, but the thread draining that client's stderr
  closes its pipe at end of file, asynchronously. When the thread was
  late, the first count included the pipe, which then closed during the
  rounds, and the second count was one lower. The test now waits for the
  drain thread before each count. A failure names the descriptors that
  appeared or went.
