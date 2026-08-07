# Phase 11B Controlled Program Target Authorization Design

Status: **Passed**

## Outcome

Phase 11B removes the service coordinator's hard-coded dependency on the literal quietshield.connection-probe application identity while preserving exact activation binding.

The generalized authorization remains limited to one explicitly approved executable per controlled activation:

- exact absolute program path
- exact SHA-256 of that executable
- deterministic path-derived stable application identity
- exact approved rehearsal ID
- Blocked or AllowedOnAll only
- exact deterministic QuietShield.ProgramLock.<id> rule ownership
- LocalSystem-only real Firewall backend
- immutable transaction record, backup, verification, rollback, and last-known-good recovery

The existing Phase 10B probe identity remains accepted only as a backwards-compatible legacy identity when the activated executable is exactly QuietShield.ConnectionProbe.exe.

## Additional safeguards

- reparse-point approved targets are refused
- Windows-directory targets are refused by the controlled installer
- QuietShield desktop and service executables are refused as approved targets
- customer-facing Install / Start / Apply / Enforce / Block Now controls remain absent
- network-specific policies remain simulation-only
- DNS activation remains blocked and was not attempted

## Dry validation

- Windows PowerShell 5.1 parsing: Passed
- Debug x64 build: Passed
- Release x64 build: Passed
- Visual Studio Release x64 build: Passed
- complete automated test suite: Passed
- Phase 11B architecture regressions: Passed
- Release service package: Passed
- generalized authorized-program installation WhatIf: Passed
- service count after validation: 0
- Program Lock rule count after validation: 0
- protected persistent Windows state: Unchanged

The next gate is a separately approved real rehearsal against a renamed controlled non-system test target. No installed customer application is authorized by this design step.
