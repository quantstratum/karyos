### Added

- Multi-destination unicast, manual mode, step 2 of 3 (karyos#630):
  - A slow optional destination is removed instead of holding the
    others (MD-7): one whose queue stayed full for a whole cycle. A
    required destination still bounds the publisher.
  - Send faults stay with their destination (MD-12): its queue is retried,
    and after three consecutive faults an optional destination is removed
    and a required one held, never an endpoint reset.
  - Removals are reported with their reason through
    `EmbeddedDriver::network_removed_destinations`
    (`DestinationRemoval`, `RemovalReason::{Slow, Fault}`). A removed
    destination's SMs and NAKs are ignored, and it no longer counts for the
    strategy edge or the restart position.
  - Reliable channels with destinations are accepted. Each destination has
    its own repair path and repair queue, with a fair share of the job
    table, so a retransmission reaches only the destination that asked
    (MD-8).
