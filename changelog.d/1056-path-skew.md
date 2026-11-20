### Added

- A channel URI key `path-skew=<duration>` (0 to 1 s, owner item 17), consumed by both sides of the channel: the sender absorbs NAK copies on other paths within it and the receiver's images wait it before NAKing or sealing a gap, in place of the driver's `path_policy.skew_window` and `path_skew_window` (default 1 ms, unchanged). Validated once at channel admission; every handle of one subscription key must ask for the same value; a conflated view of an unreliable channel checks its far-window bound with the channel's value. `UdpConfig` gains `path_skew` (karyos#1056).
