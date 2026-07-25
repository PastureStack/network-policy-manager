# Security policy

Report suspected vulnerabilities privately to the organization maintainers. Do not include production identifiers, policy documents, topology data, credentials, or exploit details in a public issue.

The offline parser rejects inputs larger than 2 MiB, duplicate or unknown JSON fields, multiple documents, oversized collections, invalid references, ambiguous labels, malformed selectors, and malformed ports. Its output excludes submitted identifiers and label content.

The live agent requires host networking and `CAP_NET_ADMIN` because it enforces forwarding policy. It does not use the host PID namespace, a container-engine socket, host filesystem access, API credentials, or secret input. Metadata responses are size- and time-bounded. Raw metadata, selectors, labels, addresses, and policy documents are excluded from logs and health responses.

The firewall backend owns only `table inet pasturestack_policy`. Updates are validated and applied in one nftables transaction. Temporary metadata or policy failures preserve the last-known-good table; bounded stale handling is explicit and observable. Cleanup requires `cleanup --yes` and removes only that exact table. Catalog-managed deployments may instead enable `--cleanup-on-exit`; it runs only after the reconcile loop has stopped and removes the same exact table during a graceful stack removal.
