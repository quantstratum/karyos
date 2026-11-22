### Fixed

- The Archive's verification worker clears its "verification runs" flag before it sends the answer, so a client that posts the next `VerifyRecording` the moment the first answers is no longer refused as busy; the flag is still cleared on a panic (karyos#1135).
