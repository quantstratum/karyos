### Added

- Clients attach network images with ADR-0100's parent-aware attach (karyos#844).
  - **Rust client.** It sends `AddImageSubscriptionOf`, naming the network subscription each image was announced to, so the reader adopts its awaiting cell at the image's join. A network subscription therefore reads messages offered between the publication's connection and its own attach.
  - **`ImageJoinLoss`.** The event reaches the subscription as an image change: `ImageChange::join_loss` is `Some(JoinLoss { from, to })` after the image's attach. `JoinLoss::new` and `ImageChange::with_join_loss` build them for other sources.
  - **C ABI.** `karyos_image_change` gains `join_loss_from` and `join_loss_to`, and `KARYOS_IMAGE_CHANGE_SIZE_JOIN_LOSS` (64) is its size with them. A caller with the 24 or 48 byte struct gets none, as with any sized output. This stays in C ABI 0.1.7, the version ADR-0100's batch 2 started, still unreleased.
  - **Conformance.** The `subscription.await_image` op and the scenarios that use it are kept: it still checks that the intended receiver's image exists, which connection does not mean.
