### Added

- `ContextBuilder::attach_timeout` (and `Context::attach_timeout`): the
  longest wait per message of `Client::connect`'s attach, apart from a
  control call's timeout, which it defaults to; once attached, the
  session's fetches of a grant's regions wait the call timeout again. A
  client whose calls time out fast need not attach as fast.
  `karyos_client::ipc::attach_with` takes both, and
  `karyos_sys::ipc::set_timeouts` and `receive_timeout` set and read a
  socket's (karyos#851).
