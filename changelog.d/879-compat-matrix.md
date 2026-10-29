### Changed

- The wire compatibility matrix's admission entries say why the refusal
  still names no driver version between 0.1.0-alpha.2 and main
  (karyos#879): a main driver states its version, but a 0.1.0-alpha.2
  client does not read it and a 0.1.0-alpha.2 driver states none.
