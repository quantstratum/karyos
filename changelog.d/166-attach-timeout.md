### Added

- `ContextBuilder::attach_timeout` (and `Context::attach_timeout`): the
  longest wait per message of `Client::connect`'s attach, apart from a
  control call's timeout, which it defaults to. A client whose calls time
  out fast need not attach as fast. The remote late-grant tests use it:
  their 50 ms timeout is for the paused request, and under load it timed
  out the attach instead (plan 166).
