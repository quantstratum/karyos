### Added

- `EmbeddedDriver::await_network_images` and `EmbeddedDriver::subscribe_image_of` (karyos#1067, ADR-0100 decisions 1 to 6): an in-process network subscription of the embedded API awaits its images, so each image of its key gets a reader cell at its join, which `subscribe_image_of` adopts in place: the reader reads what the image received before the attach. The in-process twin of `AddImageSubscriptionOf`. Without a cell to adopt (never awaited, taken, or a required cell past `image_join_deadline`), it returns the new `DriverError::NoAwaitingCell`, and a caller joins at the head with `subscribe`. `remove_network_subscription` withdraws the subscription's awaiting entry and cells.

### Fixed

- `karyosd --replica` reads each incarnation of the source from its join, so it no longer misses a replication request's first messages (karyos#1067). The source sends a request's status and payload once, from its incarnation's position 0, as soon as the replica's image exists; the replica subscribed on a later duty at the image's head, and on a loaded host the messages were already there, so it waited for payload that had gone by and counted nothing.
  - Fallback: a replica that still follows an incarnation past its start (no awaiting cell) leaves, so the source asks again from its start, unless a newer incarnation comes within a grace of twice the source's reconnect settle and first backoff (ADR-0102 decision 7). A restarted replica that first follows the source's old incarnation at its tail thus meets the new one.
  - A source whose request finished (caught up on demand, or ended) keeps watching its forward publication for a bounded time, probing the replica with the final status; a replica lost and back for the reconnect settle is asked again from the start (ADR-0102 decision 7). The watch then closes the forward publication, which a finished request kept open before.
- Two tests no longer fail on a loaded host (karyos#1067):
  - `a_replayed_group_reaches_no_network_output` fails only after 30 s without progress in a phase, not after 30 s for the whole test, and fails at once if replay returns more events than recorded.
  - `the_synthetic_profile_adds_its_spin_to_each_stage` checks a lower bound that load cannot break: every send and receive sample of a 50 us spin is at least 50 us. It no longer compares timings with the trusted profile.
