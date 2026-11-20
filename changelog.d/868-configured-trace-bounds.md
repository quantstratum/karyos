### Changed

- The driver publishes its configured `max_trace_points_per_client` and `max_trace_point_registrations_per_client` as the gauges `trace points per client` and `trace point registrations per client`, and the management agent's `limits` answers them for `trace.points_per_client` and `trace.point_registrations_per_client` instead of the defaults; with no attached driver the defaults stay (karyos#868).
