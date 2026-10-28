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
  - A removed destination retires once its queues are drained and its
    removal reported (design 3.7): its queues and route close and its slot
    is freed (`destinations_retired`), so moving an optional destination
    any number of times never fills the table. Its address is kept for its
    quarantine (MD-14); a destination added back is a fresh one, with a
    fresh repair path.
  - Each destination's repair cap is the job table's share for
    `MAX_DESTINATIONS` (MD-8), so additions never overcommit it: a reliable
    multi-destination publication needs `repair_jobs` of at least 16.
  - An optional destination whose route or queues cannot open is removed
    after three tries (`RemovalReason::Fault`), and a change on a
    publication being removed answers `DestinationChange::Removing`.
  - `network_removed_destinations` keeps the newest 16 removals;
    `network_removals_overwritten` counts the older ones.
