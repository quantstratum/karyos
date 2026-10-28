### Added

- `ContextBuilder::socket_timeout` (and `Context::socket_timeout`): the
  longest wait per message on a remote client's driver socket, the attach
  and every later fetch of a grant's regions, for the client's whole life,
  apart from a control call's timeout, which it defaults to. A client whose
  calls time out fast need not attach or fetch as fast (karyos#851).

### Fixed

- A remote client whose fetch of a grant's regions timed out marks its
  session out of step, as for any message of no fetch of its own, so a
  manifest arriving late is never read as the next fetch's (karyos#851).
- The remote late-grant tests set a 50 ms timeout so that their paused
  request times out; the attach and the late grant's fetch waited as
  little, and under load timed out first. They now set the socket timeout
  apart (karyos#851, plan 166).
