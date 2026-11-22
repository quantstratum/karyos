### Fixed

- A NAK control group entry a channel's `nak-control` adds to the driver's table is counted per subscription key and leaves the table with its last user, so channels naming more than eight distinct groups over time no longer exhaust it; configured entries stay. A key joined to an entry counts it even when its own channel has no `nak-control`, and a second handle of a key whose `nak-control` names groups the key did not join is refused with `DriverError::ControlGroupConflict`. `EmbeddedDriver::network_control_groups_in_use` reports the entries in use (karyos#1086).
