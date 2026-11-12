### Added

- A `control-mode=dynamic` publication can be built inside the driver
  with its registration allowlist (#644, step 3a): its endpoint binds the
  channel's `control` address and answers a REGISTER from an allowed source
  with one SETUP ANNOUNCE, tested on loopback. A second dynamic
  publication of one stream on one control endpoint is refused with
  `DriverError::DynamicPublicationExists`. The public publication and
  subscription calls still refuse `control-mode=dynamic` until the
  receiver side and its end-to-end tests land.
