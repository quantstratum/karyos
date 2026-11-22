### Changed

- The codec derive takes a tied field, `#[field(with = PATH, spans = [(OFFSET, WIDTH), ...])]`: one value whose bytes sit at block offsets that are not adjacent, read through `PATH::read(&block)` and written through `PATH::write(&mut encoder, &value)`, with every span checked against the template's block length and against every other field (karyos#1104). `StartRecording`, `Replay`, `RecordingDescriptor` and `RecordingSignal` are derived with it; their wire encoding is unchanged and every existing vector decodes and encodes exactly.
