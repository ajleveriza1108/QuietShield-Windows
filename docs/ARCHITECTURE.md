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

Windows owns operating-system integration contracts and implementations. The foundation implements only read-only adapter and DNS discovery. Every other service returns an explicit deferred result. `ITransactionalWindowsChange<TPlan,TBackup>` requires preflight, backup, apply, verification, rollback, and last-known-good recovery before any future mutator can conform.

### QuietShield.Service

The service project is a normal, compilable generic-host executable. It contains a cancellable diagnostic heartbeat only. It is not configured with `UseWindowsService`, has no service-registration package, and is never installed by repository scripts.

### QuietShield.Licensing

Licensing owns portable contracts and models for the universal three-device pool, server-controlled seven-day trial, reinstall continuity, private administrator entitlement, temporary offline grace, device management, refresh, and protected-token storage. It contains no endpoint, key, certificate, token, or fingerprint algorithm.

## Result semantics

Windows integrations return `Succeeded`, `NotImplemented`, `Unsupported`, `Failed`, or `Cancelled`. `NotImplemented` and `Unsupported` are first-class states; the UI must never translate either into active protection.

## Build layout

`Directory.Build.props` routes generated content to `artifacts/bin` and `artifacts/obj`, separated by project and configuration. `Directory.Packages.props` is the only package-version source. `global.json` selects SDK 10.0.302 with stable patch roll-forward only.
