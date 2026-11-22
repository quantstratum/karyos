### Changed

- Guarded concurrent publications through the C ABI, part (e) of karyos#1102 (ADR-0092). This lifts GC-7 for guarded concurrent publications.
  - **`karyos_publication_poll_outcomes`** on a concurrent handle delivers the records of its own blocks on lane 0 when its stream is guarded. Before, a concurrent handle always had none. Any other lane stays `KARYOS_E_INVALID_LANE`.
  - **Offers and claims** of a guarded concurrent handle report `KARYOS_E_GATED` and `KARYOS_E_RATE_LIMITED` as an exclusive handle's do. Before, they reported an unknown client error.
  - Timed lanes stay exclusive: a schedule on a concurrent stream is still refused.
