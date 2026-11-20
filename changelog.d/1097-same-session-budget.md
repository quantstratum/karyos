### Changed

- `ContainerConfig::session_budget` and `ApplyError::BoundsUnheld` document that every replica must use the same session budget: a replica with a smaller one stops at the logged bounds with `BoundsUnheld(OverBudget)` while the others go on (karyos#1097).
