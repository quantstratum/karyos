### Fixed

- Three karyos-driver subscribe tests no longer fail under load (karyos#1067). Stressed four in parallel on one host, they failed in 29 of 60 runs; now in none. Two waits were wrong, and no release was lost.
  - `a_dropped_network_subscription_removes_its_images` waited for the driver's registration count to reach 0 right after the client saw the image. The driver thread publishes that count after its duty cycle, so the wait could pass on a 0 read before the image's registration was counted. The client was then never served, and its release was never sent. The test now waits for the registration before dropping the subscription.
  - `the_facade_removes_a_retired_images_subscription` stopped reading its subscription once the image retired. A retired image whose clean end is not positioned yet is held by the subscription and released only at a later poll (`Images::settle_held`, by design), so the registration stayed. The final wait now keeps reading.
  - `start_join::a_refused_remote_grant_leaves_the_cell_awaiting` waits for its network subscription by a 120 s deadline, not 200 duty cycles.
