# Network Policy Manager

This repository provides a network-policy compiler and a host enforcement agent for PastureStack. The agent reads the local metadata endpoint, validates a bounded topology and policy snapshot, and installs one exact, independently owned nftables table on each host.

PastureStack is an independent community effort to preserve, audit, and modernize the Rancher 1.6 ecosystem. It is not affiliated with or endorsed by Rancher Labs or SUSE.

**Upstream:** [`rancher/network-policy-manager`](https://github.com/rancher/network-policy-manager). This GitHub fork retains the upstream Git history, authorship, dates, and license notices unchanged; PastureStack maintenance is consolidated into one commit after the preserved upstream boundary.

## Status

The default command remains a non-mutating audit compiler. `serve` is the enforcement mode used by the Catalog package. It supports live metadata reconciliation, deterministic rule compilation, an atomic nftables transaction, health status without identifiers, bounded stale-data handling, and exact cleanup.

The runtime uses host networking and requires `CAP_NET_ADMIN`. It does not require the host PID namespace, a container-engine socket, a host filesystem mount, API credentials, or secret input. Ordinary shutdown preserves the last-known-good table so an image update cannot create an enforcement gap. Catalog-managed deployments use `--cleanup-on-exit`, which removes only the owned table after a graceful stack removal. Operators that prioritize continuous enforcement during an external rolling update can omit that flag and use the explicit cleanup command when uninstalling.

## Input

Input is read from standard input or an explicit `--file` path. The maximum document size is 2 MiB. Duplicate fields, unknown fields, multiple JSON documents, dangling references, ambiguous label inheritance, and unbounded collections are rejected.

```json
{
  "schema": "pasturestack.network-policy-snapshot/v1",
  "local_host_id": "host-a",
  "stacks": [
    {"id": "application", "system": false},
    {"id": "platform", "system": true}
  ],
  "services": [
    {
      "id": "frontend",
      "stack_id": "application",
      "labels": {"tier": "web"},
      "links": ["backend"]
    },
    {
      "id": "backend",
      "stack_id": "application",
      "labels": {"tier": "api"}
    }
  ],
  "workloads": [
    {"id": "frontend-a", "host_id": "host-a", "stack_id": "application", "service_id": "frontend"},
    {"id": "backend-b", "host_id": "host-b", "stack_id": "application", "service_id": "backend"}
  ],
  "policy": {
    "default_action": "deny",
    "rules": [
      {"within": "linked", "action": "allow"},
      {
        "from": {"selector": "tier in (web,worker)"},
        "to": {"selector": "tier=api"},
        "ports": ["443/tcp"],
        "action": "allow"
      }
    ]
  }
}
```

Network addresses, credentials, keys, certificates, command strings, and enforcement settings are deliberately absent from the offline audit schema.

## Policy contract

Each rule uses exactly one form:

- `within` accepts `stack`, `service`, or `linked`.
- `between.selector` relates all non-system workloads matched by one selector.
- `between.group_by` relates non-system workloads that share a value for one label key.
- `from` and `to` select directed source and local-destination sets; optional ports accept `1` through `65535`, with optional `/tcp` or `/udp`.

Selectors are comma-separated AND expressions. Supported clauses are label existence, `=`, `==`, `!=`, `in (...)`, and `notin (...)`. Keys and values are matched case-insensitively. A negative clause matches only when the label exists and differs; a missing label never satisfies `!=` or `notin`.

Service labels are inherited by workloads. A workload may repeat an inherited label with the same case-insensitive value, but a conflicting value is rejected. Service links and direct workload links are treated as bidirectional relationships for `within: linked`. System stacks are counted but excluded from user-rule estimates.

The selector and directed forms are compiled by the live agent. Rules are evaluated in the submitted order, followed by the default action. System workloads remain outside the application default-deny set and may initiate platform traffic.

## Output and privacy

The output contains only schema and action names, inventory counts, rule-form counts, relationship estimates, safety flags, and a SHA-256 digest of the normalized input. It does not emit submitted identifiers, selectors, labels, link names, or label values. Validation errors use field positions rather than echoing invalid values.

The live `/status` and `/readyz` responses follow the same privacy boundary: they expose only version, timestamps, counts, state, and the normalized policy digest. Logs do not print raw metadata, labels, selectors, workload addresses, policy documents, or command scripts.

## Enforcement mode

```sh
network-policy-manager serve \
  --poll-interval 20s \
  --fail-open-after 10m \
  --health-listen 127.0.0.1:8092 \
  --cleanup-on-exit
```

The agent creates only `table inet pasturestack_policy`. Each replacement is validated and committed as one nftables transaction at a priority before the existing forwarding chains. Established and related replies are preserved. If metadata or a new policy is temporarily invalid, the current table remains in place. After the configured stale interval, the default availability-safe behavior replaces it with an allow-only owned table and reports `degraded`; reconciliation restores enforcement when valid metadata returns.

An operator can remove only the owned table explicitly:

```sh
network-policy-manager cleanup --yes
```

The container image uses Ubuntu 26.04 and requires host networking plus `NET_ADMIN`. Do not grant a container-engine socket or host PID namespace.

## Build and test

```sh
go test ./...
go test -race ./...
go vet ./...
go build -trimpath -o bin/network-policy-manager ./cmd/network-policy-manager
```

Run `sh scripts/validate.sh` on Unix-like systems or `pwsh -File scripts/validate.ps1` on Windows for formatting, tests, vetting, module verification, and reproducible-build checks.

## Licensing

The inherited root `LICENSE` is preserved byte-for-byte and contains the Apache License 2.0 text. Go toolchain notices used for reproducible builds are included under `LICENSES/`. See `ORIGIN.md` for the preservation and release boundary.
