### Added

- The SPEC §13 "Multi-destination isolation" contract test under `tagged` (karyos#645): `test_multi_destination_isolation_tagged_stopped_optional_is_removed`, and the full-table ERR case now checks by count that the table is left unchanged. With the existing `min`, `max`, required, retransmission and full-table tests every clause of the row is pinned except the authenticated registration one, which belongs to the authenticated capability (ADR-0076).
