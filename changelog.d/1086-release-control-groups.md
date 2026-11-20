### Fixed

- A NAK control group entry a channel's `nak-control` adds to the driver's table is counted per subscription key and leaves the table with its last user, so channels naming more than eight distinct groups over time no longer exhaust it; configured entries stay. `EmbeddedDriver::network_control_groups_in_use` reports the entries in use (karyos#1086).
