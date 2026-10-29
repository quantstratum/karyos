### Fixed

- Follow-up to the #831 and #837 reviews (karyos#827, karyos#824):
  - The drain of a remote client found gone reads a 0-byte datagram
    queued before its close as a datagram, not as the end of the stream,
    so the `Detach` behind it is served.
  - A failed `poll` of the peer reads as hung up: a real end of file is no
    longer taken for empty datagrams.
  - A closed client that gives no exit proof counts as faulty after its own
    bound (1 s), not `fetch_deadline`, and the driver logs a diagnostic
    naming the client.
  - A skipped `ECONNRESET` no longer takes a datagram of the drain's bound.
  - A closed client's time is the step's clock reading, and the exit
    check runs once per drain.
  - `karyos.h`'s `karyos_client_add_publication` says that an unsupported
    channel (CnC code 13) leaves 0 in `detail.code` and the stream id in
    `detail.value`, and an ABI test pins it.
  - The sizing report checks the stream cap with the driver's own check.
