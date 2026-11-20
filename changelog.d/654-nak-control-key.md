### Added

- A channel URI key `nak-control=<group:port>[;...]`, one multicast NAK control group per path, maps through the driver's one control group table (`NetworkConfig::nak_control_groups` seeds it, unchanged): a conflicting mapping is `DriverError::ControlGroupConflict`, a ninth entry `DriverError::ControlGroupsFull`, and an ambiguous path mapping is refused at parse time. `UdpConfig` gains `nak_control`. No group discovery is added (karyos#654).
