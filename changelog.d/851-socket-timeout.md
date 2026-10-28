### Added

- `ContextBuilder::socket_timeout` (and `Context::socket_timeout`): the
  longest wait per message on a remote client's driver socket, the attach
  and every later fetch of a grant's regions, for the client's whole life,
  apart from a control call's timeout, which it defaults to. A client whose
  calls time out fast need not attach or fetch as fast (karyos#851).
