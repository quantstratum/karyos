### Added

- `bindings_adopted` and `bindings_adoption_refused` sender counters: an
  SM from a second source of a bound receiver adopts a binding of its
  own, at most `MAX_PATHS - 1` per binding an answer created, removed
  with it; one more is refused and leaves no state.
