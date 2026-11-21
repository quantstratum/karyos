### Added

- `karyos-catalog verify` reports each copy the copy catalog commits, with its location, state and enforcement (immutable attribute, object lock or none), in text and JSON (`copies::replay_current` reads them without opening the catalog for writing). The running Archive's retention releases each removed segment's immutable attribute before a purge deletes it (karyos#1087).
