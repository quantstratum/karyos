### Added

- The driver publishes each stream lane's wire `stream_id` and its
  publications in the counters region (karyos#885), so a tool can tell
  which wire stream a lane carries and count its publishers. Each lane
  has a `stream wire id` gauge, with the lane's stream keys, whose value
  is the `i32` id zero-extended (`karyos_sys::counters::wire_stream_id`
  reads it back, a negative id included), and an `embedded publications`
  gauge counting the embedding program's live publication handles on it,
  a pending cutover's included. Each client publication has a
  `publication` gauge keyed `KIND_PUBLICATION` with its registration id,
  whose value is its client's id. A lane's publications are its
  `publication` cells plus its `embedded publications`. All are kept by
  the positions pass and change no layout version; at the default limits
  the default region holds every cell.
