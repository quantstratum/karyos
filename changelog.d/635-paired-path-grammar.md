### Added

- The channel URI grammar of paired unicast paths, `paths=<interface>@<endpoint>;...` (1 to 4, owner item 11), recorded in `CHANNEL-URI.md` section 6 and parsed into the new `Destination::PairedPaths`, with typed refusals for a repeated interface or endpoint, two address families, a mixture of paired and unpaired elements, too many paths, and any other destination key. `paths` with `destinations` is now a URI `Conflict` in either order. Drivers still refuse paired paths with `UnsupportedChannel` until unicast paths pass on real sockets (karyos#624; part of karyos#635).
