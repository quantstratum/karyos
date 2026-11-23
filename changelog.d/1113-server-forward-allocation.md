### Changed

- The Archive's control server reuses the buffers of the answers it has sent, and the batch each replication forwarding pass takes, so forwarding a running replication allocates nothing (karyos#1113). Before, every forwarded replication message allocated an encoding buffer, and every forwarding pass allocated a batch.
