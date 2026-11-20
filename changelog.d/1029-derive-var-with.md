### Added

- The codec derive takes one lifetime, variable fields (`#[field(var, min, max)]`, `&str` or `&[u8]`), fields of any type through a `with` module (`#[field(offset, width, with)]`) and a message check (`#[message(check)]`). `ControlResponse` is derived with them, byte for byte as before (karyos#1029).
