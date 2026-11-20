### Added

- A channel URI key `linger=<duration>` (0 to 60 s, the duration grammar) sets how long a removed publication keeps serving repair and repeating its EOS, overriding the driver's `publication_linger` (default 5 s, unchanged) for that publication; validated once at channel admission. `UdpConfig` gains `linger`. `path-skew` stays an unknown parameter until sender and receiver both consume it (karyos#652).
