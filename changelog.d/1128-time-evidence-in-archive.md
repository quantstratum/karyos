### Added

- The running Archive takes time evidence entries (`ArchiveHandle::record_time_evidence`) once their range is sealed, when the host made `time-evidence/`: each is durable and sealed there on return. Its head signer, shared, signs and anchors the entries' journal on the Archive's schedule and trust root (ADR-0095; karyos#1128). `karyos-catalog verify --time-requirement` now needs `--time-anchors`: the entries' journal has its own anchor store, and `--anchors` no longer stands in for it.
