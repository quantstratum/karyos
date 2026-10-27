### Added

- `karyosd --idle-image-timeout <duration>` sets the network agents'
  `idle_image_timeout`, how long stationary heartbeats keep an image alive
  after its last fresh evidence (owner item 1; karyos#638). It takes the
  channel URI's duration grammar (`ns`, `us`, `ms`, `s`), needs
  `--network on` in any order, and a bad duration is the new
  `ArgsError::InvalidDuration` with its `DurationError`. `Options` gains
  `idle_image_timeout`. The default stays 60 s.
- Tests for owner items 13 and 58 (karyos#638): a network publication with a
  local reader and a live receiver stays connected through either, so
  connected never proves remote reachability; and a `Monotonic` lane is
  refused to a client whose time namespace is proven different (two
  distinct namespace files), with that namespace's own code. The namespace
  comparison is now a function of its own, `compare_time_namespaces`, so it
  is tested without privileges. No behaviour changes.
