### Added

- Multi-destination unicast, manual mode, step 3 of 3 (karyos#630):
  - Optional destinations change at run time (MD-3). Use
    `EmbeddedDriver::add_network_destination` and
    `EmbeddedDriver::remove_network_destination`; the sender's answers
    come back through `take_network_destination_changes` as a
    `DestinationChange`.
  - An optional destination moves by a removal and an addition. A removed
    destination is quarantined for `image_liveness_timeout` before it can
    be added again (MD-14).
  - Required destinations are fixed at creation (ADR-0082): one is never
    removed or added at run time. A restart of its receiver at the same
    endpoint is rejected, so the publication's admission is
    `LostRequired`.
  - A NAK has one entry point in the sender's publication, which repairs
    toward the requester's destination on a multi-destination
    publication and on the single path otherwise.
