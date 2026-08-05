# Architecture

## Principles

QuietShield uses explicit dependency boundaries, honest capability results, cancellation-aware asynchronous contracts, central package management, and least privilege. The foundation runs as the current user and contains no elevation path.

## Dependency direction

```text
QuietShield.App --------> QuietShield.Windows ----> QuietShield.Core
      |                            ^                       ^
      +------> QuietShield.Core    |                       |
      +------> QuietShield.Licensing                      |
                                   |                       |
QuietShield.Service ---------------+-----------------------+

QuietShield.Core          (no project or package dependencies)
QuietShield.Licensing     (platform-independent, no project dependencies)
```

Tests depend on production projects only as needed. Architecture tests parse project and source files so forbidden reverse dependencies fail the build.

## Project responsibilities

### QuietShield.App

The WPF composition root owns dependency injection, logging, application lifetime, navigation, and presentation. View models contain presentation state and call contracts; XAML owns layout and visual resources. The shell uses keyboard-focusable navigation, semantic automation names, text wrapping, minimum sizing, and resource-based styling suitable for later localization.

### QuietShield.Core

Core owns protection modes, program connection policies, profiles, exclusions, schedules, activity models, parent-protected settings, validation, engine contracts, and explicit results. Its `net10.0` target and zero dependencies are enforced by tests. It must never reference presentation, operating-system, service-control, registry, firewall, DNS, native filtering, or network-discovery implementations.

### QuietShield.Windows

Windows owns operating-system integration contracts and implementations. Phase 2 provides read-only installed-application, adapter, connection-cost, DNS, Firewall-profile, WFP-capability, service, and power discovery. A coordinator runs independent queries asynchronously and returns one immutable bundle with activity, warnings, cache provenance, and cancellation. The application cache stores only the bounded inventory fields shown by the UI and expires after 15 minutes.

Read-only sources are deliberately narrow: HKLM/HKCU 32-bit and 64-bit uninstall registrations; current-user Store/MSIX identity metadata; per-user and common Start Menu shortcuts; `NetworkInterface`; fixed `Get-NetConnectionProfile`, WinRT connection-cost, Firewall-profile, and service queries; read-only TCP/IP registry values; WFP get-by-key functions; and `GetSystemPowerStatus`. There is no disk-wide scan, packet capture, command-line collection, or mutating Windows API in the discovery namespace.

`ITransactionalWindowsChange<TPlan,TBackup>` remains an unregistered future safety contract. It requires preflight, backup, apply, verification, rollback, and last-known-good recovery before any future mutator can conform.

### QuietShield.Service

The service project is a normal, compilable generic-host executable. It contains a cancellable diagnostic heartbeat only. It is not configured with `UseWindowsService`, has no service-registration package, and is never installed by repository scripts.

### QuietShield.Licensing

Licensing owns portable contracts and models for the universal three-device pool, server-controlled seven-day trial, reinstall continuity, private administrator entitlement, temporary offline grace, device management, refresh, and protected-token storage. It contains no endpoint, key, certificate, token, or fingerprint algorithm.

## Result semantics

Windows integrations return `Succeeded`, `NotImplemented`, `Unsupported`, `Failed`, or `Cancelled`. `NotImplemented` and `Unsupported` are first-class states; the UI must never translate either into active protection.

## Local policy simulation

`QuietShield.Core` owns the non-enforcing simulator. Its deterministic precedence is:

1. Safety recovery exemption.
2. Required QuietShield component exemption.
3. Explicit parent-protected restriction.
4. Active temporary allowance.
5. Active compatibility exclusion.
6. Active schedule.
7. Explicit program rule.
8. Profile default.
9. `Indeterminate` safe fallback.

Every result names the responsible rule and carries the label `Simulation only — no Windows rule was applied`. Unknown connection types never silently resolve a connection-specific rule. Schedule starts are inclusive, ends are exclusive, and overnight schedules attribute the post-midnight interval to the previous selected day.

## Build layout

`Directory.Build.props` routes generated content to `artifacts/bin` and `artifacts/obj`, separated by project and configuration. `Directory.Packages.props` is the only package-version source. `global.json` selects SDK 10.0.302 with stable patch roll-forward only.
