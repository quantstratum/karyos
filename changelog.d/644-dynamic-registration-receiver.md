### Added

- A `control-mode=dynamic` subscription can be built inside the driver
  (#644, step 3b): it registers at the channel's `control` address every
  `setup_interval` until an image of its stream from there is bound, and
  counts an ERR REGISTRATION it reads (`ReceiverCounters::registers_sent`,
  `registers_unsent`, `registration_refusals`). Loopback tests show a
  receiver registering, binding and receiving, a receiver outside the
  allowlist getting nothing, and a full table answering ERR while the
  joined destination keeps receiving. The public subscription calls now
  refuse `control-mode=dynamic` with `DriverError::DynamicRegistrationRequired`
  (before: `UnsupportedChannel`), as the publication calls do.
