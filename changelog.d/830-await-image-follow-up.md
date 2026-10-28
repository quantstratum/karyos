### Changed

- `subscription.await_image` has a defined precedence (karyos#830, review
  of #835): each round reads the pending image changes, then answers the
  first that holds, a failing image change call's status, `ok` once
  `count` is reached even when changes were dropped, `events_lost`, then
  `timeout`, so every runner answers the same.
