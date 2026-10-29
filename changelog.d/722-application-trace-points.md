### Added

- Trace record layout version 4 for application trace points (R-CORE-1,
  karyos#722, first part): point code 9, `Point::Application { id,
  metadata }`, with up to four typed metadata values (`u64`, `i64`,
  `f64`, an 8-byte ASCII tag) in words 16 to 21, refused when out of
  bounds on encode, before a sequence is taken, and on decode. Only
  application records are written as version 4; driver points keep
  version 3, so a layout 3 reader decodes them and refuses the
  application records typed. `ApplicationPoint::observe` records into a
  journal of the point's own client (`TraceWriter::for_client`) and
  refuses another's with `TraceError::ForeignPoint`; it allocates
  nothing, nor does a driver point's record with no point registered.
