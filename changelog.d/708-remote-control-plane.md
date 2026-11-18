### Added

- `karyos-control`, the control-plane component that serves the agent's API v1 to remote services over HTTPS. It accepts TLS 1.3 only, requires mutual TLS, and pins each service's certificate. It relays each request to the agent's local socket as the authenticated principal. It is not part of the default build, and `karyos-agent`'s dependencies are unchanged (karyos#708).
- `karyos-agent` accepts relayed requests from the uids named by `--relay`, for the principals of `--principal`. Each principal takes its role from the agent's own table on every request. A relay cannot grant a role, and its own role never applies to what it carries. The operations journal records the relay and the requester as separate fields. The local uid mode is unchanged (karyos#708).
