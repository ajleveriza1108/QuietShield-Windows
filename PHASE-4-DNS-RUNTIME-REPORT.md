## Files changed

- `PHASE-4-DNS-RUNTIME-REPORT.md`
- `Emergency-Restore-Dns.bat`
- `Show-DnsTransactionState.bat`
- `Test-DnsTransactionPlan.bat`
- `scripts/DnsTransaction.Script.Common.ps1`
- `scripts/Restore-OriginalDns.ps1`
- `scripts/Show-DnsTransactionState.ps1`
- `scripts/Test-DnsTransactionPlan.ps1`
- `scripts/Validate-QuietShield.ps1`
- `src/QuietShield.App/App.xaml.cs`
- `src/QuietShield.App/MainWindow.xaml`
- `src/QuietShield.App/QuietShield.App.csproj`
- `src/QuietShield.App/ViewModels/Phase2MainViewModel.cs`
- `src/QuietShield.App/ViewModels/Phase4DnsRuntimeViewModel.cs`
- `src/QuietShield.Core/Dns/DnsRuntimeContracts.cs`
- `src/QuietShield.Core/Dns/DnsTransactions.cs`
- `src/QuietShield.Core/Dns/DnsWireProtocol.cs`
- `src/QuietShield.Service/DnsRuntimeServiceCoordinator.cs`
- `src/QuietShield.Windows/Diagnostics/PrivacySafeDiagnosticExporter.cs`
- `src/QuietShield.Windows/Dns/DnsRuntimeDiagnostics.cs`
- `src/QuietShield.Windows/Dns/DnsUpstreamResolver.cs`
- `src/QuietShield.Windows/Dns/LocalDnsRuntime.cs`
- `tests/Fixtures/phase4-valid-backup.json`
- `tests/QuietShield.Architecture.Tests/RepositoryArchitectureTests.cs`
- `tests/QuietShield.Core.Tests/DnsWireAndTransactionTests.cs`
- `tests/QuietShield.Windows.Tests/DnsRuntimeAndUpstreamTests.cs`

## Runtime architecture

- `DnsWireProtocol` safely parses one-question DNS packets with bounded compression-pointer traversal, validates and normalizes the question name, retains arbitrary record types/classes, preserves transaction IDs and question metadata, and produces bounded `FORMERR`, `SERVFAIL`, and blocked-domain `NXDOMAIN` responses.
- `LocalDnsRuntime` accepts UDP and TCP on the same loopback-only endpoint. Phase 4 rejects non-loopback addresses and every requested port from 1 through 1023, including port 53; validation uses an operating-system-assigned dynamic port. Query length, concurrency, TCP backlog, request deadline, cancellation, resource cleanup, and graceful shutdown are bounded.
- Allowed packets are forwarded raw through `IDnsRawUpstreamResolver`; the runtime never uses the Windows system resolver. Indeterminate policy can fail closed or forward only to configured upstream handling. Blocked packets are answered locally without upstream traffic.
- `SafeDnsUpstreamResolver` accepts literal-IP endpoints only, tries multiple explicitly configured servers, applies bounded timeout/retry behavior, validates response transaction IDs, retries truncated UDP responses over TCP, tracks endpoint health, refuses its own listener endpoint, and permits fail-open selection only through a separately explicit emergency upstream. No production endpoint or secret is embedded.
- Runtime event records never contain packet/request payloads, URLs, credentials, page content, or browsing content. Domain fields remain null unless diagnostic domain logging is explicitly enabled.
- `DnsRuntimeServiceCoordinator` provides startup preflight, clean start/stop, cancellation, health, heartbeat, structured log events, shutdown cleanup, and failure reasons. It is not registered by `QuietShield.Service`; no Windows service was installed or registered.
- The WPF application registers only an explicit local diagnostic. Pressing **Test local resolver** starts UDP/TCP on a dynamic loopback port, performs the blocked-policy diagnostic, and stops it. Application startup does not start the runtime. The page has status/readiness fields and **Preview activation plan**, but no Activate control.

## Transaction state machine

- Normal preview/execution sequence: `Created → PreflightPassed → BackupValidated → ReadyForApproval → Applying → Verifying → Committed`.
- Verification/apply failure sequence: `Applying|Verifying → RollbackRequired → RollingBack → RolledBack`; a rollback failure ends at `RecoveryRequired`.
- Interrupted sequence: `Applying|Verifying → Interrupted → RecoveryRequired → RollingBack`.
- Preparation performs startup preflight and active-adapter selection, captures original DNS state, creates and validates the hashed backup, saves it through the backup abstraction, builds the proposed local-resolver plan, and journals `ReadyForApproval` without calling a mutator.
- Execution refuses to call the modifying abstraction unless the plan is ready, explicit user approval is present, execution is in Administrator context, the original backup validates, the local resolver is active, every adapter identity matches, and the verification deadline is future and no more than five minutes away.
- The abstract execution path applies the plan, flushes through an abstraction, verifies the QuietShield resolver and general connectivity before the deadline, then commits. An apply, verification, timeout, or cancellation failure triggers abstract restoration from the validated backup and another cache flush.
- No production `IDnsConfigurationMutator`, DNS cache flusher, or Windows activation implementation exists or is registered in Phase 4.

## Recovery design

- Backup schema 1 is secret-free and records only the QuietShield marker/purpose, backup UUID, UTC creation time, exact adapter GUID/index identities, automatic/static mode, and original IP DNS server values. A canonical SHA-256 covers the complete payload.
- C# and Windows PowerShell 5.1 independently validate marker, purpose, schema, UUID, timestamps, adapter uniqueness, IP-only server values, static-value presence, and payload hash. Unknown, malformed, altered, duplicate, or non-matching adapter state is refused.
- `Test-DnsTransactionPlan.bat` performs a read-only/WhatIf plan preview. `Show-DnsTransactionState.bat` displays recognized state or reports that none exists. Neither contains a modifying command.
- `Emergency-Restore-Dns.bat` is a manual entry point only. Its script validates the QuietShield-created backup and exact current adapter identity before reaching any restore command. A real restore additionally requires `-ExplicitUserApproval` and existing Administrator context; it never self-elevates and restores only saved automatic mode or exact saved addresses.
- Validation invoked emergency restore only with `-WhatIf` and a cryptographically valid non-production fixture whose adapter identity intentionally does not match this computer. The script refused it before any modifying command.
- Last-known-good and interrupted-transaction recovery planners are implemented against abstract repositories/journals. No production state directory or automatic recovery task is active yet.

## Test totals

- Authoritative Release x64 run: 131 passed, 0 failed, 0 skipped.
- `QuietShield.Core.Tests`: 81 passed, including DNS wire format, arbitrary record type handling, malformed/compression safeguards, response metadata, backup hash/format refusal, state transitions, guards, rollback planning, last-known-good/interrupted recovery, and adapter identity matching.
- `QuietShield.Windows.Tests`: 37 passed, including live loopback UDP/TCP, NXDOMAIN blocking, allowed raw forwarding, timeout/cancellation, concurrent requests, logging privacy, truncated UDP-to-TCP fallback, multiple upstreams, health, recursion prevention, failure policy, and service start/stop/heartbeat.
- `QuietShield.Architecture.Tests`: 13 passed, including no production DNS mutator, no app/service runtime auto-start, no port-53-capable Phase 4 runtime, no Activate control, and narrow/manual recovery-script constraints.
- Focused Phase 4 run: 4 passed for transaction-plan dry run, UDP blocked response, TCP blocked response, and allowed forwarding.

## Build results

- Windows PowerShell `5.1.26100.8875` parser validation passed for every repository PowerShell script.
- `dotnet restore` passed using the repository-local package cache.
- .NET SDK `10.0.302` Debug x64 and Release x64 builds passed with 0 warnings and 0 errors.
- Visual Studio Community 2026 `18.8.2 / 18.8.12023.21` MSBuild Release x64 passed.
- The Release WPF smoke launched, initialized, exported a privacy-safe diagnostic, closed normally, and returned exit code 0.
- Authoritative result: `logs/validation-20260806-055629.json`; complete transcript: `logs/validation-20260806-055629.log`.

## Local DNS smoke results

- UDP: passed on `127.0.0.1` with an operating-system-assigned port greater than 1023 and not port 53.
- TCP: passed on the same dynamic loopback port and stopped cleanly.
- Blocked domain: returned `NXDOMAIN`, preserved the transaction ID, and made zero upstream calls.
- Allowed domain: forwarded the raw MX query through the fake explicit upstream abstraction and returned the matching response without calling the Windows system resolver.
- Transaction dry run: validated the non-production backup fixture, reported preview-only state, and recorded that no modifying implementation was invoked.
- Emergency recovery WhatIf: refused the fixture because its adapter GUID/index did not match this computer; no restore command was reached.

## System-state comparison

- Validation remained non-elevated and identical pre/post hashes were confirmed for Windows DNS configuration, adapter IP-interface state, Firewall profiles, QuietShield services, targeted QuietShield WFP objects, QuietShield startup entries, and relevant QuietShield registry locations.
- QuietShield service count remained 0; QuietShield-owned Firewall rule count remained 0; no QuietShield WFP provider, sublayer, filter, callout driver, startup entry, certificate, registry state, or security-setting change was created.
- No Windows DNS or adapter modification ran. The only source file containing `Set-DnsClientServerAddress` is the dormant, manually invoked, guarded emergency restore script.

## Known limitations

- DNS enforcement is not active. The runtime cannot bind port 53 in Phase 4, Windows DNS is unchanged, the service coordinator is unregistered, and the application starts no persistent resolver.
- Production upstream endpoints, DNS-over-HTTPS execution, provider authentication, production trust material, and remote list/update delivery are not configured.
- The TCP listener handles one bounded DNS query per connection; connection reuse, production EDNS/DNSSEC response policy, DNS cookies, fragmentation strategy, telemetry operations, and sustained-load qualification remain future hardening work. Allowed responses are forwarded raw; locally generated error/NXDOMAIN responses retain the question but do not echo optional additional records.
- Backup/journal/recovery contracts and validation are implemented, but production protected storage, access control, retention, boot-time interrupted-transaction recovery, and an audited Windows DNS mutator do not exist.
- Emergency restore is intentionally dormant and was validated only through parsing, backup validation, architecture tests, and a WhatIf identity refusal. No restore was performed.
- The GUI readiness preview intentionally reports missing approval, Administrator context, backup, active resolver, and adapter selection. It cannot activate DNS.

## Exact Phase 5 activation procedure

1. Obtain separate written approval for Phase 5 scope, including a reviewed Windows DNS mutator, protected transaction storage, service registration, and privileged UDP/TCP port-53 operation; keep Firewall/WFP, Program Connection Lock, licensing, installer/updater, WDK, and kernel work out of scope.
2. Add and test a signed user-mode runtime build that can bind UDP and TCP loopback port 53, refuses non-loopback binding, proves no listener conflict exists, starts successfully, and reaches healthy state before any adapter plan is created.
3. Add an audited read-only preflight that confirms Administrator context without self-elevation, selects only active supported adapters by GUID/index, rejects ambiguous/unstable adapters, checks recovery-path availability, and refuses execution on any failed prerequisite.
4. Capture each target adapter's exact automatic/static DNS state and original server values, serialize the schema-versioned backup, write it atomically to an access-controlled local location, recompute and validate its SHA-256, read it back, and make the manual emergency path available before proceeding.
5. Create and journal a proposed change plan that references the validated backup and exact adapter identities and points only to the already healthy QuietShield loopback resolver. Display the complete adapter-level plan and rollback consequence to the user without applying it.
6. Require a fresh explicit user confirmation for that exact plan and a bounded verification deadline of no more than five minutes. Reconfirm Administrator context, backup validity, adapter identity, and local-resolver health immediately before apply.
7. Transition the durable journal to `Applying`, invoke the narrow Windows DNS mutator only for the approved adapters, flush DNS through the reviewed abstraction, and never change Firewall, WFP, unrelated adapters, registry policy, certificates, startup, or other security settings.
8. Transition to `Verifying`; before the deadline, verify local UDP and TCP resolver health, a deterministic blocked-domain `NXDOMAIN`, an allowed-domain upstream response, transaction-ID integrity, upstream recursion prevention, and general connectivity through independent test targets.
9. If every check passes, transition atomically to `Committed`, preserve the original backup as last-known-good recovery state, record runtime/upstream health without browsing data, and expose the verified status and manual restore path in the GUI.
10. On any apply, timeout, cancellation, resolver, or connectivity failure, transition immediately to `RollbackRequired`, restore only the exact validated original values for matching adapters, flush DNS, verify original connectivity, and finish at `RolledBack`; if restoration verification fails, mark `RecoveryRequired`, stop further activation attempts, and direct the user to the guarded manual restore procedure.
11. On startup, detect any journal left in `Applying`, `Verifying`, `RollbackRequired`, `RollingBack`, or `Interrupted`; do not reapply. Start recovery mode, validate the saved backup and adapter identities, require Administrator context and explicit approval where interaction is available, and restore/verify before normal operation.
12. Validate Phase 5 in an isolated Windows environment first, then on the target computer with pre/post DNS/adapter/Firewall/WFP/service/startup/registry snapshots, forced apply/verification/interruption failures, automatic rollback, manual restore, reboot recovery, UDP/TCP load, and service lifecycle tests. Stop without committing Phase 5 if any original state cannot be reproduced exactly.
