### Added

- Leader following and unknown outcomes on the delivery path (C10;
  karyos#686, part 3 of 5).
  - A follower forwards a client's registration or request, one hop, to
    the leader its core names, and relays the answer. The client's
    epoch and sequence are unchanged, so a forward and a retry are
    deduplicated as one request.
  - A server whose core stops leading, or changes term, answers the
    requests it took `Answer::Unknown`, never a failure. The client
    retries the same epoch and sequence, and reports `Unknown` only at
    its deadline.
  - Tests on 3 and 5 servers, over the seed corpus: a forwarded
    request; a deposed leader with a request pending; a leader change
    with a forward in flight; and a deadline. Each command runs once.
