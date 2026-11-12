### Added

- Dynamic multi-destination registration (`control-mode=dynamic`) is
  accepted (#644). `EmbeddedDriver::add_dynamic_network_publication`
  publishes on a dynamic channel to the receivers that register at its
  `control` address from a source its `RegistrationAllowlist` names; the
  allowlist is explicit and never empty (a broad range is written out,
  `0.0.0.0/0`), and it restricts admission without authenticating
  anything. `EmbeddedDriver::add_dynamic_network_subscription` registers
  a receiver with its configured `ReceiverIdentity`. Challenge and
  response, the driver's registration rates and pending bounds and the
  source checks apply to every registrant, and a full destination table
  answers one ERR REGISTRATION per source per interval.
- Required receiver ids in dynamic mode (MD-17): each has a reserved
  destination slot and two reserved pending registrations (the older one
  replaced), so optional registrants cannot fill the table ahead of it;
  admission opens once every one has joined.
- The registration lookups of the design's step 4: a receiver at its own
  destination is dropped; an optional `receiver_id` back with a new boot
  id replaces its old destination at its first status message
  (`restarted`); the same receiver at a new port moves there once its old
  destination has been quiet for `RegistrationConfig::move_quiet` (50 ms,
  `moved`), and is a `duplicate_receiver` before; a required receiver id
  is never restarted nor moved. A registrant whose receiver goes silent
  for `image_liveness_timeout` loses its slot (`timeout`), and no
  dynamic destination is announced to periodically.
- The registration counters in the CnC: REGISTERs admitted, retried,
  answered ERR or suppressed, dropped by reason, and what registrants'
  first status messages did (joined, full, refused, restarted, moved,
  timed out).
