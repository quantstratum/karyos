### Added

- `IpcConfig::client_send_buffer` (karyos#1067): the send buffer (`SO_SNDBUF`) the driver sets on each accepted admission connection. It bounds the kernel memory that one client's unread messages take, and so when a client that stopped reading is retired. `None`, the default, leaves the host's `wmem_default`, as before. A connection whose buffer cannot be set is closed. `a_client_that_stops_reading_is_retired` now uses 4096 bytes, so it no longer depends on the host: with a 128 MiB `wmem_default` the driver's socket never filled within its deadline.
