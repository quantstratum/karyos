### Fixed

- Dynamic registration, receiver side (#941; behind the refusal of
  dynamic mode on the public API): three or more dynamic subscriptions
  registering at one `control` address now bind when their publisher
  starts after them. Their REGISTERs draw on a bucket of their own per
  `control` address at the receiver, and a registrant's CHALLENGE on a
  bucket of its own per address at the sender, so REGISTERs no longer
  spend the CHALLENGE that completes a registration; each key backs off
  from `setup_interval` to sixteen times it while nothing binds, starts
  over on an ANNOUNCE from `control`, and keys are spread within an
  interval. A required receiver id is no longer kept out by a full
  bindings table while it believes it is bound: the sender keeps one
  binding free per required id not yet joined, answers no CHALLENGE of a
  dynamic publication it cannot bind (counted `challenges_unbound`, and
  `bindings_reserved` when the kept binding decides), and refuses
  `receiver_bindings` below `max_destinations` at start and dynamic
  publications whose `max_destinations` together exceed
  `receiver_bindings` (`DriverError::ReceiverBindings`). On a registering
  key a SETUP ANNOUNCE or ANSWER is taken only from its `control` address
  (`setup_not_from_control`). A client's `control-mode=dynamic` URI is
  refused as `UnsupportedChannel`, not the retryable
  `ResourcesUnavailable`. A dynamic publication's allowlist with no range
  of `control`'s family, and a dynamic subscription's `control` no
  REGISTER can reach, are refused with errors that name them
  (`DriverError::Registration`, `DriverError::InvalidRegistrationControl`),
  as are more required ids than `max_destinations`
  (`RegistrationConfigError::TooManyRequired`, before `InvalidConfig`).
