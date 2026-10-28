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
    report, with its quarantine counted from its removal (MD-14). Its
    route and queues go to the sender's close list: items still pending
    in its queues come back as `QueueClosed` and are counted in
    `removed_returned` and `removed_closed` (both now cover retired
    destinations too). Handles of an epoch older than the publication's
    died with that epoch and are dropped. The report hands its route and
    queues to the close list, which frees its slot for the next cycle's
    commands; that cycle's duty closes them before it opens any new
    route or queue, so a new destination never opens beside an old
    route. While the conductor's event ring was full, remove and add
    churn grew the per-destination state past `MAX_DESTINATIONS` and
    allocated on the duty path; an addition now answers `Full` instead,
    and a move at capacity retried after the removal shows in
    `network_removed_destinations` finds the slot free. A removal, a
    refused addition, a report with its retirement and the drain allocate
    nothing; only an accepted addition does. A close entry whose
    endpoint's TX half is not held at its duty (the half is in a reset,
    which drops the handles, or retired), or is of another epoch, is
    dropped and counted once (`removed_dropped`); a handle already gone
    counts as closed. An entry whose queue still has frames in flight is
    closed once more at the next duty (`removed_close_deferred`); one
    with a live handle the endpoint will not close is counted once
    (`removed_close_failed`). When that endpoint then refuses a route or
    a queue for its limit (`RouteLimit`, `QueueLimit`, `OverCommitted`),
    on any open path, in the same epoch, its reset is asked for once,
    tagged with that epoch; the served reset starts a new epoch, which
    drops what did not close. The endpoint table keeps this standing
    request while the endpoint is not active, within its interval, or
    with its command ring full, and serves it once in that epoch; a new
    epoch drops it. Other reset requests are dropped then, as before,
    and asked again by their owner while the need holds. Without a
    failed close in the epoch the limit is an ordinary refusal and
    resets nothing. With the
    quarantine full, the record removed earliest makes room, the
    incoming one included; an incoming record already past its
    quarantine is not kept.
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
