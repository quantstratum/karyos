### Added

- Dynamic multi-destination registration is public (karyos#644, ADR-0082): `EmbeddedDriver::add_dynamic_network_publication` publishes on a `control-mode=dynamic` channel with an explicit allowlist and optional roles, and `EmbeddedDriver::add_dynamic_network_subscription` registers a subscription with its receiver identity. Every other publication and subscription call, and a client's URI, still refuses dynamic mode, since none carries an allowlist or an identity. The refusal of karyos#944 is lifted on top of the fixes of karyos#940, #941 and #977.
