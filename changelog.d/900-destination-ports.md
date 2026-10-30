### Fixed

- The multi-destination end-to-end tests no longer add fixed loopback
  ports a receiver may have drawn from the ephemeral range, which made
  an expected `Added` report `Present` (karyos#900). Each fixed
  destination is the port of a socket the test holds open.
