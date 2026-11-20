### Fixed

- Two `karyos-sys` IPC tests no longer fail intermittently on a busy test process (karyos#1067): `readable_reports_a_pending_message_and_a_closed_peer` and `the_transport_accepts_zero_or_one_descriptor_and_rejects_the_rest` wait, within 10 s, for the peer's close after dropping its end. A test running in parallel that spawns a child forks a copy of every descriptor, so the dropped end can stay open until that child execs.
