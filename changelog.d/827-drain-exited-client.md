### Fixed

- An IPC driver now reads what an exited client queued on its admission
  socket before its exit proof releases it (karyos#827). A `Detach` the
  client sent before exiting ends its grant as a detach, so "grants
  detached" no longer misses it.
  - Only messages that release something are served; a queued `Fetch` is
    dropped.
  - An exited client is drained instead of served, never after its
    turn, so nothing is fetched or sent for it.
  - A client whose socket closes (end of file, `EPIPE` or `ECONNRESET`)
    before its exit is visible (Linux closes a dying process's
    descriptors first) is drained the same way, then retired, not as
    faulty, its slot charged until its exit proof: the new counter
    "clients closed before their exit". The end of file is confirmed with
    `POLLRDHUP`, so a 0-byte datagram from a live client stays a protocol
    error. A closed client with no exit proof within `fetch_deadline` then
    counts as faulty, and its slot stays charged until its exit proof.
  - The drain reads at most 1024 datagrams, the driver's own bound, and
    at most 8 exited clients are drained in one admission step.
  - Messages queued for the exited client are dropped unsent.
  - New driver counters: "grants released at exit" (grants whose
    descriptor left and that the exit ended), "fetches dropped at exit",
    "admission messages dropped at exit" and "admission messages not sent
    at exit" (each at exit or at a close before it), and "clients closed
    before their exit".
