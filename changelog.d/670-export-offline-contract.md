### Added

- The Retention integrity contract's last case, "an export is verified offline" (karyos#670): `test_retention_integrity_export_verified_offline` exports the contract scenario's own evidence and verifies it with the external trust only, no Archive present. Every range's offline outcome equals the online verifier's.
