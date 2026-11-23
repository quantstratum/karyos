### Added

- `Conductor::raise_to_floor` moves a registered optional or observer cell that no participant has adopted yet up to the retention floor, and returns the range it skipped. It is the karyos-sys part of ADR-0100 (karyos#844), for an awaiting cell handed over after the floor passed it. Tests show that a required cell registered when an image is built holds the image's consumption at its join until its adopter takes the same cell in place, and that the adopter reads from the join.
