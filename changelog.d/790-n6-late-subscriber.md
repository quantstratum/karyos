### Fixed

- The netem test N6 no longer fails intermittently (karyos#790). A
  multicast subscriber that missed the SETUP binds through a SOLICIT. A
  lost SOLICIT or challenge is retried only after the setup timeout and its
  holdoff, and under netem loss that could take longer than the publisher
  took to offer its 1000 messages. The image was then installed at the
  head with nothing left to read, and the test waited for a message that
  never came. The protocol behaved as specified: the test now publishes
  500 messages past the later of the two installs. The new
  `n6_a_late_multicast_subscriber_reads_the_stream_from_its_join` joins
  one subscriber after the first 1000 messages, and fails without the
  tail.
