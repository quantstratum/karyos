### Added

- The conformance op `subscription.await_image` and its feature
  `image-wait` (karyos#830, added by #835): it waits, serving every
  client, until a subscription has reported `count` images. Each round
  reads the pending image changes and answers the first that holds, in
  this order: a failing `karyos_subscription_next_image_change`'s status;
  `ok` once `count` is reached, even when changes were dropped; then, and
  only then, a failing `karyos_subscription_image_changes_lost`'s status;
  `events_lost` for a cumulative lost count above 0; `timeout` past the
  deadline. Every runner answers the same; the Rust runner and its
  precedence test share one function.
