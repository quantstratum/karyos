### Added

- W5's retries in the C5 harness (karyos#687):
  - a leadership handover in the core interface, `transfer_leadership`, whose `Unsupported` default is scored not demonstrated;
  - `Action::TransferLeadership`;
  - a server answers a client sent to a former leader with a redirect to the new one;
  - the test service keeps each client's last 10,000 answers and answers an older retry `Expired`, explicitly, without applying it again.

  The reference fixture hands over to a caught-up voter, which leads the next term. W5 adds the lost reply, leader change and retry case.
