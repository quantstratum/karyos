### Added

- Forward-compatible CnC refusal codes (karyos#819): an `Error` response
  whose code this peer does not define is read as a refusal,
  `ErrorCode::Unknown(UnknownCode)`, with its code and detail kept,
  instead of an undecodable response that left the request to time out.
  New public API: `ErrorCode::Unknown`, `UnknownCode` (its wire value,
  built only by the decoder), `ErrorCode::from_wire`,
  `ErrorCode::is_defined`, `ErrorCode::ALL` and `ErrorCode::HIGHEST`.
  Codes 0 and `u64::MAX` stay reserved. `ErrorCode::Unknown` re-encodes
  to its own wire value. The defined codes are one table, from which
  `code()`, `from_wire` and `ALL` are generated, so a new code cannot be
  left undecodable. A C client gets `KARYOS_E_REFUSED` with the raw code
  in `detail.code`. The driver never sends an undefined code (a debug
  assertion checks it in debug builds). The admission `VERSION` stays 3;
  RELEASING.md requires this change in the next release.
