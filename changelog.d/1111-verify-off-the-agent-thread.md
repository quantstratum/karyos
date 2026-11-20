### Changed

- `VerifyRecording` runs on a worker thread of its own: the agent gathers the evidence, and the worker reads the sealed ranges through a read-only view of the recording's store and answers, so a long verification no longer holds the recorders or the replays. One verification runs at a time; another is answered with an error to retry (karyos#1111).
