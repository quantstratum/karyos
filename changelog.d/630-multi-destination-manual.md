### Added

- Multi-destination unicast, manual mode, first sends
  (`quantstratum-docs: karyos/design/multi-destination-unicast.md`;
  ADR-0056, ADR-0082; karyos#630, step 1 of 3). A network publication on a
  `control-mode=manual` channel sends every datagram over unicast to each
  listed destination from one endpoint, so fan-out needs no IP multicast.
  Each destination has its own SETUP (announced until its receiver is
  live), SMs and image; answers go only to a listed destination. The
  channel's flow-control strategy and required receivers apply across
  destinations, and each destination is also held at its own window.
  `EmbeddedDriver::add_network_publication_with_destinations` names
  required destinations by endpoint; at most 16 destinations. Until the
  next steps, a destination that stops consuming holds the others,
  retransmissions are not sent, and reliable channels, guards and timed
  lanes with destinations are refused. `control-mode=dynamic` is refused
  with the new `DriverError::DynamicRegistrationUnsupported`.
