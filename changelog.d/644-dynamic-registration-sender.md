### Added

- The sender side of dynamic multi-destination registration (#644, step
  2): a REGISTER for a `control-mode=dynamic` publication goes through the
  driver's bounded admission and causes one SETUP ANNOUNCE or one ERR
  REGISTRATION to its validated source; only a pending registrant's
  CHALLENGE is answered, at its source; its first valid SM takes an
  optional destination slot, or gets one ERR REGISTRATION when the slots
  filled meanwhile. A second dynamic publication of one stream on one
  control endpoint is refused. The driver's registration limits are
  `AgentConfig::registration`. `control-mode=dynamic` is still refused at
  channel admission until the receiver side and its end-to-end tests land.
