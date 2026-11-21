### Added

- Concurrent guarded publication handles in process, part (c) of karyos#1102 (ADR-0092).
  - **`EmbeddedDriver::concurrent_publication` on a guarded stream.** It now issues a guarded handle bound to the next slot of the incarnation's shared outcome ring. A refused slot frees the handle's publisher slot. It no longer refuses with `GC-7`. After a guard close and reopen, the first call creates the stream's next incarnation, as `publication` does.
  - **`GuardBinding::new_shared`.** It binds a handle to its slot of a layout version 3 ring. Its quota `C_m` is read from the ring.
  - **`ClientConcurrentPublication::with_guard`, `guard` and `poll_outcomes`.** A guarded concurrent handle records the `(lane, start)` of each block it reserves. It answers `BackPressured` at its own quota and delivers only its own message records.
  - **`Gated` and `RateLimited`.** These are new `ConcurrentOfferOutcome` and `ConcurrentClaimOutcome` variants (pre-1.0 additions). A guarded handle reports a gate seal as `Gated`; an unguarded one still reports `Closed`.
  - **Detach.** The walker detaches a dropped in-process handle's slot, so it no longer holds the ring's room back.
