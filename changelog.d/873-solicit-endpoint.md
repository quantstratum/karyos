### Changed

- A SOLICIT for DATA that arrived on a multicast receive endpoint now
  leaves from the driver's unicast control endpoint of its address
  family, opened with the first multicast subscription and closed with
  the last (karyos#873, plan 169). The drivers of one host, which share
  the group port, are no longer one source to the publisher's
  `setup_answer_rate`. A unicast subscription's SOLICITs leave from its
  own endpoint, as before.
- The sender binds a receiver by its boot id: an SM matches its binding
  by sender endpoint, alias, boot id and incarnation, and the first
  accepted SM sets the binding's SM source, which never changes; NAKs,
  ERRs and RTTMs match and reply on it. In the trusted profile the boot
  id, not the source address, ties an SM to the receiver that solicited.
