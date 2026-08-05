# QuietShield Windows

QuietShield Windows is the C#/.NET 10 WPF foundation for a future user-controlled Windows privacy and connection-protection product. This repository currently provides domain contracts, validation, a modern accessible desktop shell, safe read-only network discovery, explicit deferred Windows integrations, a non-registered background-service executable, universal licensing models, tests, scripts, and design documentation.

> **Foundation safety status:** protection is not active. The application does not modify Firewall, DNS, adapters, services, startup, filtering, certificates, the registry, or security settings. It displays no invented protection statistics.

## Validated toolchain

- Windows 11 x64
- Visual Studio Community 2026 18.8.2 / 18.8.12023.21
- .NET SDK 10.0.302
- .NET Windows Desktop runtime 10.0.10
- Windows PowerShell 5.1
- Git 2.55.0.windows.2

Visual Studio 2022 and its native C++ toolchain remain a separate, preserved dependency foundation. This project does not modify either Visual Studio installation.

## Projects

- `QuietShield.App`: WPF/MVVM application shell and feature navigation.
- `QuietShield.Core`: platform-independent policies, domain models, scheduling, validation, activity contracts, and results.
- `QuietShield.Windows`: Windows-specific read-only discovery and explicit deferred integrations.
- `QuietShield.Service`: compilable generic-host heartbeat foundation; not installed or registered.
- `QuietShield.Licensing`: secret-free universal licensing, trial, device-pool, offline-grace, and storage contracts.
- `QuietShield.Core.Tests`: domain and licensing tests.
- `QuietShield.Windows.Tests`: Windows placeholder and service-cancellation tests.
- `QuietShield.Architecture.Tests`: dependency, package, elevation, and safety-boundary tests.

## Commands

Run from a normal, non-Administrator Command Prompt or Windows PowerShell session:

```bat
Build-QuietShield.bat -Configuration Debug
Build-QuietShield.bat -Configuration Release
Test-QuietShield.bat -Configuration Release
Run-QuietShield.bat -Configuration Debug
Clean-QuietShield.bat -WhatIf
Validate-QuietShield.bat
```

Each launcher starts `powershell.exe -NoProfile -ExecutionPolicy Bypass` for that process only. Logs are written under `logs`; packages, CLI state, intermediate files, binaries, test results, and smoke output are written under `artifacts`.

## Dependencies

Central package management is enforced by `Directory.Packages.props`. The only direct external packages are:

| Package | Version | Purpose | Licence | Projects |
|---|---:|---|---|---|
| Microsoft.Extensions.Hosting | 10.0.10 | Microsoft dependency injection, configuration, hosting, cancellation, and structured logging | MIT | QuietShield.App; QuietShield.Service |
| MSTest | 4.0.2 | Microsoft-supported automated test framework and runner integration | MIT | All three test projects |

No preview packages are used. There is no Python, Node.js, Java, Electron, WebView2, SQLite, WDK, driver, third-party networking package, production server URL, key, certificate, credential, or device-fingerprint implementation.

## Current limitations

All protection and modifying integrations are deliberately deferred. Network type and DNS discovery use read-only framework APIs. Application inventory, Firewall state, filtering-platform capability, service state, startup, notifications, battery state, licensing communication, secure storage, and system tray integration return explicit `NotImplemented` or `Unsupported` results.

See [ARCHITECTURE.md](docs/ARCHITECTURE.md), [SECURITY-BOUNDARIES.md](docs/SECURITY-BOUNDARIES.md), and [DEVELOPMENT-ROADMAP.md](docs/DEVELOPMENT-ROADMAP.md) before proposing a new phase.
