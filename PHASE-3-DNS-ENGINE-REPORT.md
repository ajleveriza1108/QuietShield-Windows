## Files changed

- `PHASE-3-DNS-ENGINE-REPORT.md`
- `docs/CUSTOM-DNS-LIST-FORMAT.md`
- `scripts/Validate-QuietShield.ps1`
- `src/QuietShield.App/App.xaml.cs`
- `src/QuietShield.App/MainWindow.xaml`
- `src/QuietShield.App/QuietShield.App.csproj`
- `src/QuietShield.App/ViewModels/Phase2MainViewModel.cs`
- `src/QuietShield.App/ViewModels/Phase3DnsViewModel.cs`
- `src/QuietShield.Core/Dns/CustomDomainLists.cs`
- `src/QuietShield.Core/Dns/DnsDecisionCache.cs`
- `src/QuietShield.Core/Dns/DnsPolicyEngine.cs`
- `src/QuietShield.Core/Dns/DnsPolicyModels.cs`
- `src/QuietShield.Core/Dns/DomainNormalizer.cs`
- `src/QuietShield.Core/Dns/ProtectionLists.cs`
- `src/QuietShield.Core/Dns/ResolverContracts.cs`
- `src/QuietShield.Core/Dns/SampleProtectionLists.cs`
- `src/QuietShield.Windows/Diagnostics/PrivacySafeDiagnosticExporter.cs`
- `src/QuietShield.Windows/Dns/ResolverFoundations.cs`
- `tests/QuietShield.Architecture.Tests/RepositoryArchitectureTests.cs`
- `tests/QuietShield.Core.Tests/DnsListCacheAndCustomTests.cs`
- `tests/QuietShield.Core.Tests/DnsPolicyEngineTests.cs`
- `tests/QuietShield.Windows.Tests/DnsResolverFoundationTests.cs`

## Architecture added

- `QuietShield.Core` now contains platform-independent domain normalization with IDN/Punycode handling, exact/domain-and-subdomain/safe-wildcard matching, deterministic DNS policy decisions, protection modes and categories, and explicit result provenance.
- Protection-list foundations provide immutable snapshots, version/created/expiry metadata, canonical SHA-256 verification, a signature-verification contract, atomic in-memory activation, last-known-good and rollback behavior, duplicate removal, conflict reporting, and a differential-update contract. Embedded rules and their verifier are explicitly non-production samples with no production key, certificate, URL, or secret.
- The custom-list service provides validated in-memory add/edit/remove/search, notes and creation dates, duplicate detection, parent-protected entries, and atomic privacy-safe JSON import/export. The format is documented separately.
- The bounded, thread-safe, non-persistent decision cache supports positive and negative entries, TTL expiration, cancellation, FIFO eviction, and manual clearing.
- Resolver contracts cover the current system resolver, future upstream DNS, DNS-over-HTTPS capability, decision caching, and explicit diagnostics. The Windows system resolver is read-only; upstream and DoH remain deferred. The optional UDP diagnostic listener is unregistered and disabled by default, requires explicit enablement, and can bind only to `127.0.0.1` on an operating-system-assigned unprivileged port.
- The WPF composition root registers only in-memory DNS simulation services. It does not register a system/upstream resolver or diagnostic listener. The DNS page shows current detected DNS configuration, simulation mode and result, protection-list/LKG status, and a custom-list editor, with an explicit statement that no Windows DNS setting has been changed.

## Rule precedence

1. Required QuietShield safety exemption.
2. Explicit custom allowlist.
3. Parent-protected block.
4. Explicit custom blocklist.
5. Threat and malware rules.
6. Protection-mode category rules.
7. Safe default: allow a valid unmatched domain in simulation; an invalid domain is indeterminate.

Ties within the same precedence level are resolved deterministically by ordinal rule ID. The result includes decision, category, normalized matched rule, all matching source-list names, reason, timestamp, and normalized domain.

## Test totals

- Authoritative Release x64 run: 100 passed, 0 failed, 0 skipped.
- `QuietShield.Core.Tests`: 67 passed, including normalization, IDN, wildcard safeguards, every precedence level, modes/categories, hashes/signatures, activation/rollback, cache TTL/eviction/cancellation/concurrency, custom-list CRUD/import/export, and diagnostic redaction.
- `QuietShield.Windows.Tests`: 23 passed, including disabled-by-default and explicit loopback/dynamic/unprivileged diagnostic-listener checks.
- `QuietShield.Architecture.Tests`: 10 passed, including no modifying DNS implementation registered and no privileged/non-loopback listener binding.
- Focused Phase 3 smoke run: 2 passed for DNS simulation and failed-activation rollback to last-known-good.

## Build results

- Windows PowerShell 5.1 parser validation passed for every repository PowerShell script; validation ran with Windows PowerShell `5.1.26100.8875` without Administrator elevation.
- `dotnet restore` passed with the repository-local package cache.
- .NET SDK `10.0.302` Debug x64 build passed with 0 warnings and 0 errors.
- .NET SDK `10.0.302` Release x64 build passed with 0 warnings and 0 errors.
- Visual Studio Community 2026 `18.8.2 / 18.8.12023.21` MSBuild Release x64 build passed.
- Authoritative results: `logs/validation-20260806-051933.json`; complete transcript: `logs/validation-20260806-051933.log`.

## GUI smoke result

- The Release x64 WPF application launched, initialized the Phase 3 in-memory DNS/list foundation, produced its requested privacy-safe diagnostic summary, closed normally within the smoke interval, and returned exit code 0.
- The separate DNS policy simulation and protection-list activation/rollback smokes passed. No enforcement action or invented blocked-request total is present.

## System-state comparison

- Pre/post snapshots were identical for Windows DNS server configuration, adapter IP-interface state, Windows Firewall profiles, QuietShield services, targeted QuietShield WFP objects, QuietShield startup entries, and relevant QuietShield registry locations.
- Validation remained non-elevated; QuietShield service count remained 0; QuietShield-owned Firewall rule count remained 0; no QuietShield WFP provider, sublayer, filter, callout driver, startup entry, or registry state was created.
- Validation found no registry mutation, certificate, or security-setting mutation command in the repository scripts.

## Known limitations

- Phase 3 is simulation-only. It does not change Windows DNS, intercept or redirect traffic, bind port 53, enforce rules for other applications, alter adapters or Firewall, register services, create WFP objects, or persist browsing history.
- Protection lists, last-known-good state, custom entries, and decision-cache entries are in memory only and reset when the application exits.
- Only clearly marked `.test` sample rules and a non-production sample signature verifier are included. Production list distribution, trust keys, signing, downloads, and differential-update application are not implemented.
- Direct upstream DNS and DNS-over-HTTPS execution are deferred. The optional loopback diagnostic listener is a foundation/test component and is not registered by the application.
- The Custom mode contract accepts an explicit category set, but the Phase 3 GUI does not yet provide category-set editing. JSON import/export is available through the service contract and documented format, without a GUI file picker.
- The WPF smoke validates launch, initialization, diagnostic export, and clean exit; it is not full UI automation. Policy behavior is covered by deterministic automated tests.

## Exact next recommended phase

Phase 4 — user-approved local settings and simulation-profile persistence only: define a versioned privacy-reviewed settings schema; add migrations, corruption recovery, atomic writes, explicit reset/import/export, and parent-protection authorization semantics while keeping DNS enforcement, Firewall/WFP changes, services, licensing communication, installers, updates, WDK, and kernel work disabled and separately reviewable.
