### Changed

- `karyos-client`: a network subscription holds back a retired image's change until the image's clean end is positioned (the driver announces the retirement before it positions the seal), so `karyos_subscription_next_image_change` no longer reports a clean end at position 0 when it is not (karyos#1067). It goes without a position after 10 000 adoptions.
- Tests: more load-sensitive tests from karyos#1067. The two-path driver tests wait, bounded, for the second path to bind before their first message; the min-gate repair loop is bounded by time; the one-local-gap test asks for both paths' heartbeat sources, at least; and the tool attach rollback test checks that no descriptor is left open instead of comparing counts, which a previous test's late close could lower.

- Tests: the karyos-tools verify tests route their last direct integrity journal open through the bounded retry. A child another test spawns shares the journal's `flock`ed file description until its exec closes it (macOS included), so an open right after a drop can see `Locked` for that instant (karyos#1067).
