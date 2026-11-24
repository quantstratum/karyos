### Added

- A relayed `gap-ack` (R-CORE-19, karyos#726) answers with the interval it acknowledged and that its events remain unknown, `{"acknowledged":{"position","reason","from","to"},"events":"unknown"}`, so a console cannot show the acknowledgement as a repair, and refuses a position that is no open unknown interval with `"refusal":"not_an_unknown_interval"`. It stays an administrator action, and the journal records the authenticated requester and the relay as separate fields of the unchanged `GapAcknowledged` record. The local answer is unchanged.

### Changed

- `Server::bind` refuses a relay id of 0 with `ServeError::ZeroRelay`, as the CLI already did: 0 is the local socket's, and a relay under it would be served the local answers (karyos#726).
