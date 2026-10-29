### Changed

- A driver that refuses a client's, tool's or probe's protocol version
  now states its own in the refusal (karyos#879): word 1 of `Refused`
  with `INCOMPATIBLE_VERSION`, 0 before, is the refuser's version. The
  layout and its length are unchanged, so every client of every version
  decodes it as before. `AttachError::IncompatibleVersion { driver }`
  and the C ABI's `detail->value` report it; a refusal of
  0.1.0-alpha.2 or earlier states none and still reports 0. Read it
  with `Message::refuser_version`, build it with
  `Message::incompatible_version`; word 1 of every other refusal stays
  the fetch id.
