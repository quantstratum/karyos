### Added

- The optional borrowed-term TX operation (karyos#771, R-CORE-45 part
  2). `TxBackend::submit_borrowed` queues the frames of a `ReadLease` as
  one datagram. Its default stages: it claims a frame, copies the lease
  into it byte for byte as a copy read gives, commits it, and ends the
  lease. The sockets backend, and every backend that does not borrow,
  behaves as before. A refusal hands the lease back, still held, with a
  typed `BorrowError`. A backend that borrows keeps its leases in a
  `LeaseLedger`, allocated at creation for the sender's bound. A lease
  is released only when a completion or a returned item proves the bytes
  are no longer referenced. A reset (`begin_reset`) waits for every
  lease and past the retirement bound reports `ResetDrain::Stuck`,
  counted once, keeping the leases so their terms stay pinned. Leasing,
  staging and the ledger's hold and release allocate nothing.
