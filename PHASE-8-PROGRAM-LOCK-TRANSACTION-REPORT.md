# Phase 8 — Program Connection Lock Transaction and Rollback Framework

## Outcome

Phase 8 is complete on `feature/connection-lock-transaction-framework`. QuietShield now has deterministic Program Connection Lock rule identities, preflight decisions, non-executable rule plans, immutable verified backups, a transaction state machine, exact verification, rollback, interrupted recovery, and emergency-recovery simulation.

No real Windows Firewall or Windows Filtering Platform enforcement implementation exists or is registered. The Windows capability implementation is read-only. The Phase 5 DNS blocker evidence and activation prohibitions remain unchanged.

## Enforcement strategy

- Windows Firewall is the first future user-mode layer for policies it can represent exactly.
- Blocked and Allowed on All are classified as statically representable.
- Wi-Fi Only and Ethernet Only require runtime network-transition management and are emitted as unsupported by the current static planner.
- Cellular Only, Metered Only, and Unmetered Only require a separately reviewed future user-mode WFP design and are emitted as unsupported.
- Kernel callout drivers remain deferred.

The complete support matrix and rationale are in `docs/PROGRAM-LOCK-ENFORCEMENT-STRATEGY.md`.

## Transaction and recovery framework

- Deterministic `QuietShield.ProgramLock.<stable-rule-id>` identity includes the ownership marker, schema, profile, exact Win32 or MSIX identity, policy, direction, protocol, network scope, creation transaction, display metadata, and description.
- The state machine implements Draft through Committed, rollback and restoration, safe pre-apply failure, and interrupted recovery. Every failure after ApplyStarted requires rollback or interrupted recovery.
- Preflight returns explicit blockers and warnings for privilege, service capability, profile and application validity, missing/moved targets, MSIX support, owned-rule inventory, transaction conflicts, active connection type, enforceability, and emergency readiness.
- Backups validate exact QuietShield ownership, schema, application identities, policies, rule order, per-rule hashes, and a SHA-256 payload hash. Writes are atomic, last-known-good state is retained, and transaction history is append-only JSONL.
- Plans contain Add, Replace, Remove, Preserve, Unsupported, or NoChange operations with exact future rule identity, action, scope, reason, future privilege, verification, and rollback counterpart.
- Identical desired state is idempotent; a hypothetical second application produces NoChange.
- Recovery simulations cover normal and partial rollback, application crash, shutdown, stale transaction, profile switch, missing executable, malformed backup refusal, and emergency removal limited to QuietShield-owned rules.

## Implementations and scripts

- Modifying contracts have in-memory and fixture implementations only.
- `ReadOnlyProgramLockWindowsCapability` reports Firewall/BFE capability, existing QuietShield-owned count, policy support, and confirms that no modifying implementation is registered.
- PowerShell 5.1-compatible transaction test, state viewer, and restore scripts validate exact ownership/schema/hash data.
- Emergency restore supports `-WhatIf`, requires explicit approval and an already elevated console for any future real use, never self-elevates, and deliberately refuses execution because Phase 8 has no modifying Windows implementation.
- Root launchers use Windows PowerShell 5.1 safety flags.

## GUI

Program Connection Lock now displays transaction, profile, policy-support, operation-count, backup, rollback, and emergency readiness. The only Phase 8 actions are Preview Enforcement Plan and Export Plan. The recycling-virtualized plan viewer displays application, simulated policy, proposed operation, enforceability, reason, future privilege, rollback action, and rule ID with long-text tooltips.

The page prominently states: “Enforcement is not active. No Windows Firewall or WFP rule has been changed.” No Apply, Activate, Enforce, or Administrator button is present.

## Authoritative validation

- Result: Passed
- Validation JSON: `logs/validation-20260806-104749.json`
- Complete log: `logs/validation-20260806-104749.log`
- Windows PowerShell: 5.1; every script parsed successfully
- .NET SDK: 10.0.302
- Visual Studio 2026 Community/MSBuild: 18.8.2 / 18.8.12023.21
- Debug x64 build: Passed with zero warnings and zero errors
- Release x64 build: Passed with zero warnings and zero errors
- Visual Studio 2026 MSBuild: Passed
- Automated tests: 270/270 passed
  - Core: 183
  - Architecture: 41
  - Windows: 46
- Explicit Phase 8 smoke selection: 40/40 passed
- WPF launch, all-page navigation, transaction preview, and plan export: Passed
- Responsive layouts: Passed at 1024×640, 1366×768, and 1920×1080
- Scaling model: Passed at 100%, 125%, 150%, and 200%
- Long-text, keyboard, focus, virtualization, backup, rollback, interrupted-recovery, and emergency-restore `-WhatIf` smokes: Passed

## Protected Windows state

Validation ran without Administrator elevation. Before/after snapshots confirmed unchanged Firewall, WFP, DNS, adapters, services, registry, and startup state. No certificate, security policy, Windows setting, Firewall rule, WFP object, or real enforcement state was changed.

The Phase 5 DNS activation prohibition and append-only attempt evidence remain unchanged. Real Program Connection Lock enforcement is not active and must not begin without a separate explicit approval.

## Next phase

Phase 9: separately review a real Windows Firewall Program Connection Lock implementation and controlled UAC rehearsal. Do not begin real enforcement automatically.
