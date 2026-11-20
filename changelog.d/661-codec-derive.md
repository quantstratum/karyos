### Added

- `karyos-codec-derive`: `#[derive(Message)]` writes the `decode` and `encode` of a codec message of fixed fields, each at its offset with an optional check. `StopRecording`, `ListRecordings` and `StopReplay` use it, byte for byte as before. `make codec-derive-check` (in pre-push) shows `syn`, `quote` and `proc-macro2` in no runtime graph and that the derive adds no `syn` major (karyos#661).
