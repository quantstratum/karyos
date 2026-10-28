### Added

- Multi-destination unicast, manual mode, step 2 of 3 (karyos#630):
  - A slow optional destination is removed instead of holding the
    others (MD-7): at the first datagram its full queue cannot take while
    the others take it, with no grace, counted in `removed_slow`. It is
    never removed while the publisher is held by a required loss, while
    the shared socket pushes back, or while it bounds the others under
    `min` or inside a `tagged` group. A required destination still bounds
    the publisher.
  - Send faults stay with their destination (MD-12): its queue is retried,
    and after three consecutive faults an optional destination is removed
    (`removed_fault`) and a required one held. A queue that refuses its
    retry is counted (`retries_refused`) and, for a required destination,
    goes to the control path, which resets the endpoint.
  - A removed destination gets nothing more, its EOS included, and no
    longer keeps a lane from idling or draining: the others still get
    their heartbeats and the publication's EOS. One that fails to open on
    a new epoch no longer holds the others.
  - Removals are reported with their reason through
    `EmbeddedDriver::network_removed_destinations`
    (`DestinationRemoval`, `RemovalReason::{Slow, Fault}`). A removed
    destination's SMs and NAKs are ignored, and it no longer counts for the
    strategy edge or the restart position.
  - Reliable channels with destinations are accepted. Each destination has
    its own repair path and repair queue, with a fair share of the job
    table, so a retransmission reaches only the destination that asked
    (MD-8).
