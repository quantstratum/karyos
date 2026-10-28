### Fixed

- An IPC driver now reads what an exited client queued on its admission
  socket before its exit proof releases it (karyos#827). A `Detach` the
  client sent before exiting ends its grant as a detach, so "grants
  detached" no longer misses it.
  - Only messages that release something are served; a queued `Fetch` is
    dropped.
  - The drain is bounded by `max_exports_per_client +
    max_fetches_per_client + 1` messages.
  - New driver counters: "grants released at exit" (grants the exit
    ended), "fetches dropped at exit" and "admission messages dropped at
    exit".
