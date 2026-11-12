### Changed

- `DriverError::DynamicRegistrationUnsupported` is renamed
  `DriverError::DynamicRegistrationRequired` (#644): the network
  publication and subscription calls that carry no registration refuse a
  `control-mode=dynamic` channel with it. A dynamic subscription needs a
  configured receiver identity; with none it registers nowhere (before:
  it named the boot id's first word, which is not stable across
  restarts).
