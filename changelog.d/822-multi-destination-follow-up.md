### Fixed

- Multi-destination unicast, the follow-up of its run-time destinations
  (karyos#822, plan 157):
  - A publication removed before the sender's next duty now closes the
    routes and queues of the destinations retired since that duty's
    drain; they used to stay open until an endpoint epoch change.
  - A removed destination holds its slot until its removal is reported,
    which now happens only once its queues are drained. While the
    conductor's event ring was full, remove and add churn grew the
    per-destination state past `MAX_DESTINATIONS` and allocated on the
    duty path. An addition now answers `Full` instead. A move at capacity
    retried after the removal shows in `network_removed_destinations`
    finds the slot free: the addition retires the reported destination
    first. A removal is retired in the cycle it is reported. A removal, a
    refused addition and the drain of retired destinations allocate
    nothing; only an accepted addition does. The sender's close list has
    a fixed capacity, and what does not fit waits for the next duty
    (`close_deferred`).
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
