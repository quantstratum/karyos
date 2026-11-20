### Added

- Time evidence entries of ADR-0095: `karyos_archive::integrity::time_evidence`, with each typed refusal, an `EntryStore` that appends and seals entries in `time-evidence/` (its own integrity journal), and an entry's verdict against a requirement. `karyos-catalog verify --time-requirement NS:GRAN` reports the time verdict per entry and combined, apart from integrity. It reports `met` only for entries the entries' journal verifies under the trust and the anchors (`--time-anchors` names that journal's anchor stores) (karyos#1065).
