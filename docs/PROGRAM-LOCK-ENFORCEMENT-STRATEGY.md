# Program Connection Lock Enforcement Strategy

Phase 8 defines transaction, backup, verification, rollback, and recovery behavior only. No Windows Firewall or Windows Filtering Platform object is created, changed, enabled, disabled, or removed.

## Layer order

1. Use application-specific Windows Firewall rules when the policy can be represented completely and verified safely.
2. Consider user-mode Windows Filtering Platform only when Windows Firewall cannot represent the required connection semantics safely.
3. Keep kernel callout drivers deferred.

## Policy support matrix

| Policy | Phase 8 classification | Future layer | Reason |
|---|---|---|---|
| Blocked | Statically representable | Windows Firewall | An exact outbound application block is deterministic. |
| Allowed on All | Statically representable | Windows Firewall | The desired state is the verified absence of QuietShield-owned restrictions for that application. |
| Wi-Fi Only | Requires Runtime Network Transition Management | Windows Firewall plus runtime transitions | Static interface scopes cannot safely cover every simultaneous, virtual, and changing adapter topology. |
| Ethernet Only | Requires Runtime Network Transition Management | Windows Firewall plus runtime transitions | Static interface scopes cannot safely cover every simultaneous, virtual, and changing adapter topology. |
| Cellular Only | Requires Runtime Network Transition Management | Future user-mode WFP | Windows Firewall has no reliable static cellular-only scope. |
| Metered Only | Requires Runtime Network Transition Management | Future user-mode WFP | Metered cost is dynamic and is not a reliable static Firewall rule scope. |
| Unmetered Only | Requires Runtime Network Transition Management | Future user-mode WFP | Network cost can change without a static Firewall rule transition. |

The planner emits `Unsupported` operations for connection-specific policies until their separately reviewed runtime manager exists. It never labels a static rule plan as enforceable when the policy requires dynamic network state.

## Rule identity and ownership

Every proposed rule is owned by the exact marker `QuietShield`, uses schema version 1, and has a deterministic name in the namespace:

`QuietShield.ProgramLock.<stable-rule-id>`

The stable ID hashes the profile ID, stable application identity, policy, direction, protocol, and network scope. Display name is presentation metadata and never identifies a rule.

## Transaction boundary

The only provided creators, updaters, removers, rollback handlers, and interrupted-recovery handlers operate on in-memory or fixture state. The Windows implementation is read-only capability inspection. No modifying implementation is registered in application dependency injection.
