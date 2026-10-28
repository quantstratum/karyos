### Fixed

- Multi-destination unicast, the follow-up of its run-time destinations
  (karyos#822, plan 157):
  - A publication removed before the sender's next duty now closes the
    routes and queues of the destinations retired since that duty's
    drain; they used to stay open until an endpoint epoch change.
  - A removed destination is retired as a removed publication is: its
    removal is reported in the cycle it happens, whatever the state of
    the publication (served or not, established or not) or of its
    queues (an endpoint reset included), and it is retired at that
    report. Its route and queues go to the sender's close list: items
    still pending in its queues come back as `QueueClosed` and are
    counted in `removed_returned`, as for a removed publication, and
    another epoch's handles are skipped. Until its report it holds its
    slot: while the conductor's event ring was full, remove and add
    churn grew the per-destination state past `MAX_DESTINATIONS` and
    allocated on the duty path. An addition now answers `Full` instead,
    and a move at capacity retried after the removal shows in
    `network_removed_destinations` finds the slot free. A removal, a
    refused addition, a report with its retirement and the drain
    allocate nothing; only an accepted addition does. When the sender's
    fixed close list has no room, retired routes and queues are carried
    over to the next duty (`close_deferred`), and a retirement that finds
    the retired list full waits with its slot (`retire_deferred`):
    nothing is dropped.
  - A route table, queue entries or TX slots that other publications
    filled (`RouteLimit`, `QueueLimit`, `OverCommitted`) no longer count
    as the destination's own fault, so an optional destination is not
    removed for them. They are counted in the new `endpoint_limits`
    counter; a reset or a stale handle is not.
  - A destination whose open failed is retried once per
    `setup_interval` in that epoch, at once in a new one, instead of on
    every serve.
  - A publication whose initial destinations are not all of the shared
    endpoint's address family, or whose endpoint address is unknown, is
    refused at creation (design 3.1). An unknown address is no longer
    taken for IPv4.
