### Fixed

- Three tests that failed on a loaded host now wait on the event they check, within a bounded deadline (karyos#993): the OIDC key set lifetime test gives its set five seconds of lifetime and waits for the refusal instead of sleeping a fixed second, the hello timeout test advances its clock until the close is seen, and the zero linger test removes its publication only once the sender's session is established.
- The `karyos-ffi` tests that open C drivers no longer fail with `KARYOS_E_HANDLES_EXHAUSTED` (300) on a host with more than eight test threads (karyos#993): the driver table holds `KARYOS_MAX_DRIVERS` (8) per process, and every such test now takes its drivers' slots from one crate-wide test pool first.
