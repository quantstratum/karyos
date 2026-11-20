### Changed

- The Archive's signing poll keeps only the journal records not yet covered by a signed head (and the key registry records the registry replay reads), dropping the covered prefix, so its cache no longer grows with the journal; `HeadSigning::poll_from` and `HeadSigning::covered` let a caller sign over such a window (karyos#1095).
