### Fixed

- Follow-up to the #814 review (R-CORE-21, karyos#740):
  - A network sender gate built for a lane guarded with no rate creates
    its bucket from the first policy published to its slot, so a rateless
    lane's publication getting a policy is limited at the gate too, not
    only in its handles. Positions such a gate let through before are
    exempt: never charged, never refunded into the adopted bucket, and
    never charged again for another route's copy.
  - A bucket created for a policy taken at run time, the gate's or a
    handle's copy, starts empty (`RateLimiter::empty`): a change never
    grants tokens. A handle that binds to a policy in force, read whole,
    starts full, as a lane guarded with it does; one whose read at bind
    found the policy being written starts empty. A reincarnation's gate
    starts its bucket empty (`GuardSpec::full`), so reincarnating never
    buys a new burst.
  - The driver validates a byte burst against the largest charge its
    sender gate does, the MTU aligned as a frame (it used the MTU), so a
    policy it accepts and audits is never one the gate refuses. Were the
    gate to refuse one anyway, it fails closed: it limits with the
    stricter of that policy and the one in force, counted in the new
    per-publication CnC cell `network rate policies refused`, which the
    agent reports.
  - A gate built for a publication whose policy changed starts from the
    policy in force. Freeing retired streams drops the freed
    publications' stored policies in one pass over the lanes left.
    `GateCounts` is `#[non_exhaustive]`.
