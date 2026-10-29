### Changed

- Multi-destination unicast repairs within the configured tables, and
  catches each destination up alone after an endpoint reset (MD-8, MD-20,
  karyos#802).
  - **The reset:** a reliable publication no longer rewinds its shared
    readers and resends to every destination. Each destination gets, per
    lane, one repair job over what it lacks:
    - it starts where its own submissions stop, at its `high`, or lower
      where a head was returned unsent earlier in the epoch (a later
      submitted head would otherwise pass that hole);
    - it ends at the readers' position;
    - nothing goes to a destination that already has it.

    The job takes a slot in the destination's share with no admission and
    no ERR. A full share leaves the catch-up waiting to be tried again, and
    a part below the retention floor is counted lost
    (`catch_ups`, `catch_ups_full`, `catch_up_lost` in the repair counts).
  - **The tables:** the ERR linger entries, the job linger entries and the
    step 8 replies are now shared out per destination as the job table is,
    `value / max_destinations`. A value below one entry per destination is
    refused (`RepairConfigError::TableShare`). The tables of every
    destination together stay within the configured ones, and the sender's
    reply list holds every destination's ERRs, so none is dropped for room.
