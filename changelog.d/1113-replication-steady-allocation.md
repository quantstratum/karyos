### Changed

- A continuous replication's steady duty allocates nothing on the source (karyos#1113, karyos#996). `Outgoing::Bytes` carries a `Chunk` that derefs to its bytes and gives its buffer back to the `Sender` once dropped, so each chunk reuses a pooled buffer; `Sender::poll` finds the next range without collecting; the agent reuses its journal and message buffers, reads new seals through the new `IntegrityJournal::records_from_into`, and drops the seals already sent.
