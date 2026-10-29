### Fixed

- The images-in-turn test (`client_facade.rs`,
  `a_network_subscription_polls_its_images_in_turn`) read before both
  images held their messages: under load, one image's datagrams arrived
  after the reads began, and the first reads rightly took the only image
  with data. A second subscription of the channel now witnesses that both
  images hold all 16 messages before the first is read one at a time
  (karyos#853, plan 167). No timeout is longer.
