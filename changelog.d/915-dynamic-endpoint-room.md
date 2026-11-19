### Fixed

- A `control-mode=dynamic` network publication now holds the routes, queues and TX slots of `max_destinations` destinations of its endpoint from its admission, and is refused with `DriverError::EndpointCapacity` when the endpoint cannot hold them (karyos#915, design 3.5): its registrants open their routes on the sender thread, where no admission runs, so an endpoint could otherwise be outgrown at run time. Manual multi-destination publications keep the per-destination admission of karyos#859.
