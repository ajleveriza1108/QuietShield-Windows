# Network safety and rollback

## Foundation behavior

Only `System.Net.NetworkInformation` read operations are used to enumerate adapter state and DNS server addresses. Metered cost is reported as unknown because a safe implementation has not been approved. Firewall, WFP, routing, proxy, service, startup, and DNS mutation APIs are not called.

## Required future transaction

Every network-changing operation must:

1. Preflight privileges, ownership, policy conflicts, active adapters, remote-management risk, and current connectivity.
2. Capture a minimal redacted backup with provenance and schema version.
3. Apply a narrowly scoped, idempotent transaction.
4. Verify both configuration and real connectivity without leaking destinations.
5. Roll back immediately on failure, cancellation, timeout, or partial apply.
6. Retain an authenticated last-known-good state for crash recovery.

The operation must preserve third-party VPN, endpoint-security, enterprise policy, Hyper-V, virtual adapters, and user customizations unless a reviewed incompatibility requires an explicit choice.

## Failure rules

- Never claim active protection from request acceptance alone.
- Never continue after failed backup or ambiguous ownership.
- Prefer no change over partial protection.
- Bound retries; do not flap adapters or DNS.
- Do not strand remote sessions.
- Record redacted steps and result codes without destinations, queries, credentials, or user content.

## Advanced WFP boundary

Any WFP provider/filter/callout work requires a separate design for filter ownership, weights, sublayers, boot-time behavior, BFE availability, transactionality, stale-filter cleanup, service failure, upgrade, uninstall, and recovery. Kernel callouts remain deferred WDK work.
