### Added

- Timers and configuration changes through the log on the delivery
  path (C10; karyos#686, part 4 of 5).
  - A `DeliveryServer` that leads proposes `TimerFired` for every
    scheduled timer that is due, and a new leadership proposes them all
    again. A firing applied twice delivers once.
  - `with_configurations` delivers a core's own configuration entries to
    the service as changes, instead of stopping the container.
    `Delivery::Change` takes an operator's membership change.
  - Tests on 3 and 5 servers: a timer fires at its own entry on every
    replica, after the request that set it; a configuration change is
    delivered at its entry; a restored leader proposes due timers again,
    and each fires once.

  `AppendService` now does nothing for a command it does not know,
  instead of reporting a reply too large.
