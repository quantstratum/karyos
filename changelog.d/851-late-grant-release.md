### Fixed

- A remote client releases a late grant even when the fetch that takes it
  times out (karyos#851). Before, the take failed, the release was not
  counted, and what the abandoned fetch exported stayed held until the
  client's next fetch drained it. Now `Client::poll` drains abandoned
  fetches without waiting (`RemoteClient::drain_abandoned`), so their
  exports are detached at once, and the release removes the grant's
  registration itself. The remote late-grant tests also retry a request
  whose fetch timed out under load.
