### Changed

- API: `NetworkPublicationState` is not `#[non_exhaustive]`, so its new
  `Limited` variant breaks an exhaustive `match` in client code, and
  `NetworkConfig` gains a public field, which breaks a struct literal
  without `..NetworkConfig::default()`.
