# Phase 2 — Read-Only Windows Discovery and Policy Simulation

## Outcome

Phase 2 is complete and validated on the approved foundation. QuietShield now discovers bounded Windows application and capability state, presents the results in WPF, and simulates local policies without enforcement. Protection remains inactive. No Administrator elevation, software installation, package change, system repair, Firewall/DNS/adapter/service/startup/registry/certificate mutation, WFP object creation, traffic capture, remote communication, Git remote, or push occurred.

- Branch: `feature/read-only-discovery`
- Baseline: `7f671a7a0d83aa7eecaa8d2833f481110ca49c8c`
- Final validation: `Passed`, 2026-08-05 21:57:18 +08:00
- Final Phase 2 commit: recorded in the final handoff because this report is part of that commit

## Architecture changes

- `QuietShield.Core` adds a dependency-free deterministic policy simulator and result models.
- `QuietShield.Windows` adds immutable inventory/network/DNS/Firewall/WFP/service/power models, cancellable discovery contracts, a 15-minute JSON inventory cache, network-change notifications, and a parallel read-only coordinator.
- Privacy-safe diagnostics are a separate projection. Sensitive live fields such as adapter names, descriptions, DNS addresses, application names, paths, and icons never enter the diagnostic model.
- `QuietShield.App` composes only read-only Phase 2 services. The WPF view model performs asynchronous refresh/cancel/cache/export actions and local simulation. Resume refresh uses `WM_POWERBROADCAST`; network refresh uses `NetworkChange`.
- Foundation network/view-model source files remain in the repository for history but are excluded from compilation and replaced by the Phase 2 implementations.
- The future transactional mutation contract remains unregistered.

## Discovery sources

Application inventory uses only:

- HKLM/HKCU uninstall registrations in both 32-bit and 64-bit registry views.
- Current-user Store/MSIX package identity fields from `Get-AppxPackage`.
- `.lnk` entries below the Windows-defined per-user and common Start Menu roots; only target paths are read, never shortcut arguments.
- Top-level executable candidates only when an uninstall registration provides a credible install location; no recursive drive scan.
- `FileVersionInfo` and associated icons only for confidently resolved executable paths; no normal-discovery executable hashing.

Windows capability discovery uses `NetworkInterface`, fixed `Get-NetConnectionProfile` and WinRT cost queries, read-only TCP/IP DNS registry fields, Firewall profile/count queries, fixed service queries, WFP get-by-key APIs, targeted callout-service keys, and `GetSystemPowerStatus`. All PowerShell child processes use constant scripts, `-NoProfile`, `-NonInteractive`, and current-user privileges.

## Deterministic policy precedence

1. Safety recovery exemption.
2. Required QuietShield component exemption.
3. Explicit parent-protected restriction.
4. Active temporary allowance.
5. Active compatibility exclusion.
6. Active schedule.
7. Explicit program rule.
8. Profile default.
9. Safe fallback to `Indeterminate`.

Every result identifies the responsible rule and says `Simulation only — no Windows rule was applied`. Unknown logical/physical connection conflicts remain `Indeterminate`. Schedule starts are inclusive, ends are exclusive, and overnight schedules use the previous selected day after midnight.

## Privacy protections

- No traffic, packets, browser content/history, DNS queries, messages, keystrokes, file contents, public IP lookup, Wi-Fi SSID/location, device serial, MAC address export, licence value, token, credential, private key, or complete command line is collected.
- Cache fields are limited to the UI inventory model and contain no uninstall command, shortcut arguments, browser data, document data, or executable hashes.
- Diagnostics are created only after an explicit UI or validation-smoke action.
- Diagnostics contain counts/types/booleans/versions and redact user-profile paths, username, IPv4/IPv6 addresses, MAC addresses, and common secret/token assignments.
- Detailed unrelated third-party Firewall rules are not displayed; a bounded query outputs only the QuietShield-owned count.

## Actual detected read-only state

- Installed applications after safe deduplication: **704**
  - System component: 371
  - Microsoft Store/MSIX: 81
  - Win32: 124
  - Unknown/Start Menu only: 128
- Primary network type: **Wi-Fi**
- Connection cost: **Unmetered**
- Network category: **Public**
- Adapter classifications: Wi-Fi 6, Ethernet 16, other 1, VPN/virtual 27
- DNS adapter configurations: 50 (Automatic 2, Mixed 2, Unknown 46)
- Encrypted DNS capability: exposed by live discovery when Windows makes the command available
- QuietShield DNS Protection: **Not active**
- Firewall profiles: Domain enabled; Private enabled; Public enabled
- QuietShield-owned Firewall rules: **0**
- WFP user-mode API: available; future changes require elevation
- QuietShield WFP provider/sublayer/filters/callout driver: **absent / absent / 0 / absent**
- QuietShield Service: not registered and not running
- BFE, Windows Firewall, and Network List services: registered and running
- Power: AC connected; battery present at 80%; Battery Saver off at discovery time

These values are a point-in-time result and can change naturally after validation.

## Validation

- Windows PowerShell 5.1 parser: passed for every script (`5.1.26100.8875`).
- `dotnet restore`: passed.
- Debug x64 build: passed, zero warnings/errors.
- Release x64 build: passed, zero warnings/errors.
- Visual Studio 2026 MSBuild Release x64: passed.
- Automated tests: **57/57 passed**.
  - Core: 30
  - Windows: 19
  - Architecture: 8
- Application inventory smoke: passed.
- Network/DNS/Firewall/WFP/service/power discovery smoke: passed.
- Policy simulation smoke: passed.
- Privacy-safe diagnostic export smoke: passed.
- WPF launch smoke: passed, exit code 0.
- Non-Administrator execution: passed.
- Clean launcher safety: passed in `-WhatIf` mode; nothing was removed.

The validation workflow initially exposed a read-only WPF `Run.Text` binding configured with the control's default two-way mode. The binding was changed to explicit one-way mode, a focused Release WPF smoke passed, and the complete validation then passed from a fresh pre-snapshot.

## Pre/post safety comparison

The final validation compared snapshots taken immediately before and after the build/test/smoke workflow:

- Firewall profiles: unchanged.
- DNS server configuration: unchanged.
- Network adapter/IP-interface configuration: unchanged.
- Registered QuietShield services: unchanged; count remained zero.
- QuietShield WFP provider/sublayer/callout ownership: unchanged and absent.
- QuietShield startup entries: unchanged and absent.
- Relevant QuietShield registry key structure: unchanged and absent.
- Administrator elevation: false.
- Registry/certificate/security mutation commands in scripts: none.

Final validation artifacts are intentionally ignored by Git and remain under `logs` and `artifacts/test-results`.

## Known limitations

- Windows exposes connection cost as the active Internet connection profile; it is applied as best-effort metadata to operational adapters.
- VPN/virtual classification combines interface type with conservative name/description markers and can classify unusual vendor adapters as `Other` or `Unknown`.
- DNS automatic/manual origin is determinable only where the accessible TCP/IP interface registry data is unambiguous; IPv6 and virtual adapters often remain `Unknown`.
- Store display names use accessible package identity names and may not be localized marketing names.
- Start Menu targets using activation protocols or indirection are retained as non-launchable/unknown rather than guessed.
- A future pre-existing QuietShield WFP provider would be detected, but this bounded phase deliberately does not enumerate its filters; the validated baseline has no provider and exactly zero filters.
- Discovery reports point-in-time capability state; it does not account for traffic or monitor processes.
- Startup, tray activation, settings persistence, licensing communication, enforcement, updater, installer, Private Browser, WDK, and driver signing remain deferred.

## Exact files changed

- `PHASE-2-READ-ONLY-DISCOVERY-REPORT.md`
- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/DEVELOPMENT-ROADMAP.md`
- `docs/PRIVACY-DESIGN.md`
- `scripts/QuietShield.Script.Common.ps1`
- `scripts/Validate-QuietShield.ps1`
- `src/QuietShield.App/App.xaml.cs`
- `src/QuietShield.App/ApplicationIconConverter.cs`
- `src/QuietShield.App/MainWindow.xaml`
- `src/QuietShield.App/MainWindow.xaml.cs`
- `src/QuietShield.App/QuietShield.App.csproj`
- `src/QuietShield.App/ViewModels/AsyncRelayCommand.cs`
- `src/QuietShield.App/ViewModels/Phase2MainViewModel.cs`
- `src/QuietShield.Core/Simulation/PolicySimulationModels.cs`
- `src/QuietShield.Core/Simulation/PolicySimulator.cs`
- `src/QuietShield.Windows/Diagnostics/PrivacySafeDiagnosticExporter.cs`
- `src/QuietShield.Windows/Discovery/Applications/ApplicationDiscoverySources.cs`
- `src/QuietShield.Windows/Discovery/Applications/ApplicationInventoryCache.cs`
- `src/QuietShield.Windows/Discovery/Applications/ApplicationInventoryService.cs`
- `src/QuietShield.Windows/Discovery/Applications/PowerShellStorePackageSource.cs`
- `src/QuietShield.Windows/Discovery/NetworkAndDnsDiscovery.cs`
- `src/QuietShield.Windows/Discovery/PowerShellJsonRunner.cs`
- `src/QuietShield.Windows/Discovery/ReadOnlyDiscoveryCoordinator.cs`
- `src/QuietShield.Windows/Discovery/WindowsStateDiscovery.cs`
- `src/QuietShield.Windows/Integration/DeferredWindowsServices.cs`
- `src/QuietShield.Windows/Integration/WindowsCapabilityContracts.cs`
- `src/QuietShield.Windows/Integration/WindowsCapabilityModels.cs`
- `src/QuietShield.Windows/QuietShield.Windows.csproj`
- `tests/QuietShield.Architecture.Tests/RepositoryArchitectureTests.cs`
- `tests/QuietShield.Core.Tests/PolicySimulationTests.cs`
- `tests/QuietShield.Windows.Tests/Phase2DiscoveryTests.cs`
- `tests/QuietShield.Windows.Tests/ReadOnlyWindowsServiceTests.cs`

## Exact next recommended phase

Begin only after separate approval: **Phase 3 — versioned local simulation settings and protection-profile persistence**. Keep enforcement disabled. Define atomic storage, schema migration, corruption recovery, explicit reset/export, privacy retention, parent-protection semantics, and tests. Do not combine that work with DNS or Firewall changes, WFP object creation, licensing communication, updater/installer work, Private Browser, WDK, driver signing, or kernel code.
