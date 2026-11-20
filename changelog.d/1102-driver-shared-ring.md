### Added

- Driver support for concurrent guarded streams, part (b) of karyos#1102 (ADR-0092).
  - **Guarding a concurrent stream.** `EmbeddedDriver::guard_stream` now accepts a concurrent stream with up to 64 publisher slots. Its slot count is `H`, and `H` handles of `C_m` reserved messages each must fit half a term. More than 64 slots, or a window that does not fit, is `InvalidConfig`.
  - **One shared outcome ring per incarnation.** The first guarded handle creates a layout version 3 ring, bound to the guard's open epoch and to that handle's client. A handle of another client is refused with `Sys(InvalidPublicationMode { reason: "GC-7-client" })`. One beyond `H` is refused with the new `DriverError::GuardHandleSlotsExhausted`. A slot is never issued twice in one incarnation, and a detached handle leaves the room minimum.
  - **The walker.** It writes every record of a concurrent guarded stream through `SharedOutcomeWriter`, against one consumed cell per slot. A guard close repeats `abort_marked_claims` while it reports waiting. A lapped walker faults every live handle with the new `SharedOutcomeWriter::abandon`.
  - **Unchanged for now.** `concurrent_publication` refuses a guarded stream with `Sys(InvalidPublicationMode { reason: "GC-7" })` until the client handle binds a slot (karyos#1102 part c).
