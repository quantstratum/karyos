### Added

- A unicast subscription accepts `endpoint=<host>:0`: the driver binds an ephemeral port before the subscription is ready and reports it in `NetworkSubscriptionReady` and on `Subscription::bound_address()`; a reset keeps that port. A publication refuses an `endpoint` on port 0 (`InvalidChannel`, new `ChannelConfig::check_publication`), groups, destinations and `control` keep refusing port 0, and port 0 with `paths` is a `Conflict` (karyos#656).
