### Added

- Remote concurrent guarded publication handles, part (d) of karyos#1102 (ADR-0092).
  - **Grant.** A remote client's `AddConcurrentPublication` on a guarded stream is granted with the incarnation's shared outcome ring, the handle's own consumed cell and the guard words beside its log buffer. The first handle creates the ring in a driver-only region. The consumed cell record carries the handle's slot of the ring as the new admission capability `GuardSlot { slot }` (code 6), which only that record of a guarded concurrent grant may carry.
  - **`RemoteClient::take_concurrent_publication`.** It binds a guarded grant to its slot with `GuardBinding::new_shared`, so the handle answers `BackPressured` at its quota and reads only its own message records.
  - **Refusals.** A handle beyond the stream's `H` is refused with the new `ErrorCode::GuardHandlesExhausted` (code 28), whose detail is `H`; another client's handle on the same incarnation with `InvalidPublicationMode` (`GC-7-client`). A refused slot ends the handle's publisher registration.
  - **Detach.** When a remote handle's consumed cell grant ends, its slot leaves the ring's room minimum.
