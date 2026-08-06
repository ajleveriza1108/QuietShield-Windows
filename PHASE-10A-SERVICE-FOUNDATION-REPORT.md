# Phase 10A Persistent Service Foundation Report

## Outcome

Status: **Passed**

QuietShield now has a production-structured .NET 10 Windows-service host that also runs as a safe, non-elevated console diagnostic host. Phase 10A did not install or register a service and did not activate persistent enforcement.

The validated host started, served local IPC requests, persisted health and heartbeat state, refused every modifying request, and shut down gracefully. The existing Phase 5 DNS blocker and all Phase 9 rehearsal evidence were preserved.

## Service architecture

- `BackgroundService` lifetime with cancellation, bounded shutdown, structured logging, health transitions, and heartbeat persistence
- Windows service lifetime integration through Microsoft's official .NET hosting package, without service installation or registration
- non-elevated console diagnostic mode with bounded-duration validation support
- read-only startup preflight and persistent-state integrity validation
- explicit interrupted-transaction detection and recovery-required health state
- validated last-known-good fallback without automatic enforcement
- crash-state marker written while running and a clean-shutdown marker written only after graceful stop
- invalid persistent state is refused and is not overwritten automatically

Persistent enforcement remains **Not active**. No real Windows Firewall modifier is registered.

## Initial policy support

The coordinator classifies only these policies as candidates for a future separately approved persistent enforcement phase:

- `Blocked`
- `AllowedOnAll`

Both remain read-only plan previews in Phase 10A. Wi-Fi-only and Ethernet-only policies require runtime network-transition management. Cellular-only, Metered-only, and Unmetered-only policies require a separately approved user-mode WFP and transition design. No network-specific policy is approximated by a static rule.

## Local IPC

The app/service contract uses a local Windows named pipe with the current-user-only option. It has:

- protocol version and request ID on every message
- a 64 KiB maximum framed message size
- bounded connection and request timeouts
- cancellation and reconnect handling
- malformed, empty, oversized, and unsupported-version refusal
- no TCP, UDP, HTTP, or other remote listener
- no request payload or secret logging

Validated messages:

- `GetServiceStatus`
- `GetActiveProfile`
- `PreviewPolicyPlan`
- `RequestProfileActivation`
- `RequestProgramRuleChange`
- `RequestTemporaryAllowance`
- `GetTransactionStatus`
- `RequestRollback`
- `GetHealth`
- `Ping`

Every modifying request returned exactly: `NotActive — service installation and enforcement not enabled.`

## Persistent state and recovery

Versioned state models cover active profile, program policies, temporary allowances, schedules, compatibility exclusions, transaction checkpoint, last-known-good policy, service health, and schema version.

State writes use a same-directory temporary file, write-through flush, atomic replacement, SHA-256 payload integrity, and a backup copy. Tests validated atomic replacement, backup recovery, malformed JSON refusal, hash mismatch refusal, explicit migration, unsupported-schema refusal, last-known-good fallback, and interrupted checkpoint detection. No credentials, licence keys, secrets, production device fingerprints, or hardcoded user paths are stored.

The coordinator models preflight, policy validation, deterministic plan generation, backup, apply abstraction, verification, commit, rollback, interrupted recovery, and emergency cleanup. Only read-only and in-memory implementations are registered.

## Safety exemptions

Every policy preview and audit exposes the reason for all eight required exemptions:

- QuietShield desktop app
- future QuietShield service
- future licensing refresh
- updater
- DHCP
- required DNS operations
- Windows networking
- emergency recovery

## GUI and launchers

The responsive dashboard displays:

- Service status: `Not installed`
- Service communication: `Diagnostic mode`
- Persistent enforcement: `Not active`
- active profile
- last-known-good policy status
- transaction status
- recovery readiness

No Install Service, Start Service, Apply, or Enforce control was added. The inherited GUI validation passed at 1024x640, 1366x768, and 1920x1080, at modeled 100%, 125%, 150%, and 200% scaling, with keyboard, long-text, and horizontal-overflow checks.

Safe entry points:

- `Run-Service-Diagnostic.bat`
- `Test-Service-Communication.bat`
- `Validate-Phase10A.bat`

All PowerShell remains compatible with Windows PowerShell 5.1 and refuses elevated validation.

## Validation

- Windows PowerShell 5.1 parser: Passed for every script
- `dotnet restore`: Passed
- Debug x64 build: Passed, 0 warnings and 0 errors
- Release x64 build: Passed, 0 warnings and 0 errors
- Visual Studio 2026 MSBuild Release x64: Passed
- Automated tests: **329/329 passed**
- Architecture tests: Passed
- service diagnostic launch and graceful shutdown: Passed, exit code 0
- IPC ping, status, profile-plan preview, reconnect, and refusal smoke: Passed
- persistent-state corruption and last-known-good tests: Passed
- WPF launch, navigation, responsive layout, and service-status smoke: Passed
- registered QuietShield service count before and after: **0**
- Administrator elevation: **Not used**

Primary validation evidence:

- `logs\phase10a-validation-20260806-155833.log`
- `logs\phase10a-validation-20260806-155833.json`
- `logs\phase10a-protected-before-20260806-155833.json`
- `logs\phase10a-protected-after-20260806-155833.json`

## Protected Windows state

The before/after comparison passed. Firewall, QuietShield-owned Firewall rules, DNS configuration, WFP state, adapter identity and configuration, services, registry, startup, certificates, and security settings remained unchanged. No adapter operational transition occurred during the final validation window.

## Scope boundary

No service registration, elevation, Firewall change, DNS change, WFP change, adapter change, registry change, startup change, certificate change, licensing work, trial work, installer, updater, Private Browser, Metered Data Watch, Aggressive Program Watch, or parent-control work was performed.

The exact next phase is **Phase 10B: separately approved Windows service installation and persistent Blocked/Allowed-on-All enforcement activation validation**. Phase 10B has not started.
