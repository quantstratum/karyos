### Added

- A dynamic subscription's registration is visible to its application
  (#941): `EmbeddedDriver::network_registration_state` returns
  `Registering`, `Announced`, `Refused` (an ERR REGISTRATION from
  `control`) or `Bound`, and the receiver publishes the CnC cells
  `registers sent`, `registers unsent` and `registration refusals
  received`. They are appended to the receiver's cells, so the ids of the
  cells allocated after them move by three; readers find cells by label.
