### Fixed

- A Cluster admin command sent as soon as the previous one answered is no longer refused as `busy` (karyos#1067). The worker calling the Cluster's gateway released its in-flight reservation only when it exited, after it had handed the reply over, so a caller that sent its next command at once could still find the Cluster reserved; it now releases the reservation and the gateway's lock as soon as the gateway answers. A command made while another is still in the gateway is `busy`, unjournalled and unsent, as before.
- `a_command_while_another_is_in_flight_is_busy_unjournalled_and_unsent` holds its gateway until released instead of sleeping 300 ms, so the first command is in flight for certain when the second comes (karyos#1067).
