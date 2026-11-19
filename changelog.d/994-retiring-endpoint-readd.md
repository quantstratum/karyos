### Fixed

- A network publication added while an endpoint at its fixed bind address is still retiring after its last publication went is refused with the retryable `DriverError::NetworkBusy`, and taken once the endpoint has retired, instead of failing with `NetworkEndpoint` on the bind (karyos#994). Endpoints bound to port 0 are not affected.
