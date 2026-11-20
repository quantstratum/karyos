### Fixed

- A reply to a REGISTER or a first SM whose send latches a fault on a destination's control queue (an `EMSGSIZE`, say) no longer leaves that fault in place: the queue is evicted, and the destination's next control opens a fresh one instead of stopping at the fault and being dropped. Ordinary backpressure keeps cancelling the unsent reply in place (karyos#1016).
