### Fixed

- A multi-destination network publication's membership table now holds a Pending entry and a member per destination, `max_pending` and `max_receivers` raised to `max_destinations` when it is larger (karyos#917, design 3.5): at `max_destinations` above 16 the default `max_pending` of 16 could refuse destinations that CHALLENGE at once.
