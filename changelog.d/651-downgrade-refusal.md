### Added

- Downgrade refusal tests for the `encrypted` class (karyos#651, ADR-0114 section 8): a stripped envelope, a datagram mixing protection classes, and a plaintext SETUP or RSP_SETUP are each refused with their own reason, in every domain, and no state changes. `aes_gcm_siv::check_inner_classes` refuses an envelope nested inside an opened encrypted datagram, before any inner frame takes effect.
