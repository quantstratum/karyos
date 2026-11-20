### Changed

- The driver keeps its own copy of each application trace point in the driver counters region, which clients never write (type id 8, the point's name as its label, keyed to its client, its id as its value), freed with the point; `trace-export` names `points[]` from that copy, so a client rewriting its own cell's value no longer changes an exported name. The agent's sample and `karyos-stat` leave these cells out of the driver counters (karyos#869).
