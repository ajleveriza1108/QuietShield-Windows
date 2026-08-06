# Phase 7 — Program Connection Lock Foundation

## Outcome

Phase 7 is complete on `feature/program-connection-lock-foundation`. QuietShield now has a deterministic, simulation-only Program Connection Lock foundation built on the existing read-only application inventory. It does not contain or register an executable Windows enforcement implementation.

The Phase 6 responsive GUI baseline, the DNS engine and runtime, and all Phase 5 blocker evidence and activation prohibitions remain in place.

## Implemented foundation

- Seven connection policies: Blocked, Wi-Fi Only, Ethernet Only, Cellular Only, Metered Only, Unmetered Only, and Allowed on All.
- A fixed, non-editable, non-deletable Block All profile plus a catalog limited to five editable profiles.
- Profile name, description, default policy, program overrides, duplicate-name rejection, selected-profile persistence, and privacy-safe schema-versioned JSON import/export.
- Stable Win32 executable and Microsoft Store/MSIX identities sourced from the existing read-only inventory. Display name alone is never accepted as identity.
- Explicit representation and safe refusal of missing, moved, unsupported, and ambiguous program targets, with system-component classification retained.
- Visible simulation-only safety exemptions for the desktop app, future service, licensing refresh, updater, DHCP, required DNS operations, Windows networking, and emergency recovery.
- Temporary allowances until process close, for 5/15/30/60 minutes, or until a custom expiration, including prior-policy restoration metadata and expired-entry cleanup.
- Time-zone-safe study, work, bedtime, and custom schedules with overnight evaluation, wake/resume reconciliation, and deterministic conflict resolution.
- Compatibility Guard simulations scoped to an exact program, exact normalized domain, or temporary bypass. Global silent protection disable is rejected.
- A read-only Windows enforcement planner that describes the stable target, desired policy, proposed Windows Firewall or user-mode WFP strategy, future privilege requirement, backup, application, verification, rollback, and refusal reasons. Every plan is non-executable.

## Decision precedence

The simulator evaluates rules in this fixed order:

1. Emergency recovery exemption
2. Required QuietShield component exemption
3. Parent-protected restriction
4. Active temporary allowance
5. Active compatibility exclusion
6. Active schedule
7. Explicit program rule
8. Profile default
9. Indeterminate safe fallback

Every result includes the decision, reason, matched rule, active profile, connection type, schedule result, compatibility result, and safety-exemption result. Possible decisions are Allow, Block, Require Parent Approval, Temporary Allow, Unsupported, and Indeterminate.

## GUI

The following pages now expose the simulation foundation without an Apply, Activate, or Enforce control:

- Program Connection Lock
- Protection Profiles
- Schedules
- Compatibility Guard

The application inventory remains searchable and recycling-virtualized. Icon, name, publisher, type, exact target/path status, and simulated policy context are visible. Long values trim with full-value tooltips, interactive controls participate in keyboard navigation with visible focus, and cards wrap or stack at narrow widths.

## Authoritative validation

- Result: Passed
- Validation JSON: `logs/validation-20260806-100107.json`
- Complete log: `logs/validation-20260806-100107.log`
- Windows PowerShell: 5.1.26100.8875; every script parsed successfully
- .NET SDK: 10.0.302
- Visual Studio 2026 Community/MSBuild: 18.8.2 / 18.8.12023.21
- Debug x64 build: Passed, zero warnings and zero errors
- Release x64 build: Passed, zero warnings and zero errors
- Visual Studio 2026 MSBuild: Passed
- Automated tests: 230/230 passed
  - Core: 152
  - Architecture: 34
  - Windows: 44
- Explicit Phase 7 smoke selection: 53/53 passed
- WPF launch and navigation: Passed across all 17 pages
- Responsive layouts: Passed at 1024×640, 1366×768, and 1920×1080
- Scaling model: Passed at 100%, 125%, 150%, and 200%
- Long-text, maximized-window, keyboard, focus, virtualization, inventory, profile/policy simulation, and planner smokes: Passed
- Read-only inventory smoke: 704 applications discovered

## Safety result

Validation ran without Administrator elevation. Before/after snapshots confirmed unchanged DNS, adapters, Firewall, QuietShield WFP objects, startup entries, QuietShield registry state, and service registration. No certificate or security setting was changed. No Firewall or WFP rule was created, and no enforcement plan executed.

The Phase 5 real DNS activation rehearsal remains unvalidated and disabled. Permanent DNS activation and service registration remain prohibited until the documented external UDP/TCP loopback orchestration blocker is resolved in a separately approved phase.

## Next phase

Phase 8: separately review the transactional Program Connection Lock enforcement and rollback design. No real enforcement, elevation, Firewall/WFP mutation, or Windows activation begins without explicit approval.
