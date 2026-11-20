### Changed

- `Propose::propose`, `Envelope::Register` and `Envelope::to_vec` document a host's obligation under ADR-0087: service entries go through `ServiceContainer::propose`, which holds a leader's registrations until the session bounds apply; raw bytes handed to the core bypass that gate (karyos#1062).
