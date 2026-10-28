### Changed

- A CnC `Error` response whose code a peer does not define is read as a
  refusal, `ErrorCode::Unknown(code)`, with its code and detail kept,
  instead of an undecodable response that left the request to time out
  (karyos#819). Code 0 stays reserved. `ErrorCode::Unknown` re-encodes to
  its own wire value, and the driver checks it sends only defined codes. A C client gets
  `KARYOS_E_REFUSED` with the raw code in `detail.code`. The admission
  `VERSION` stays 3; RELEASING.md requires this change in the next
  release.
