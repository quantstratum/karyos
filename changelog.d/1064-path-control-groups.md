### Fixed

- A redundant path joins its own NAK control group: each later path of a reliable multicast subscription joins the group the driver's control group table (or the channel's `nak-control`) names for its interface, the image binds it when the path is bound, every NAK is copied once to each distinct path group, and peer NAKs on any of them feed the image's suppression state. Before, only the founding path joined a control group (karyos#1064).
