# Package inventory

Package versions are controlled exclusively by `Directory.Packages.props`. Versions were taken from the installed stable .NET 10.0.302 templates and aligned with the installed .NET 10.0.10 runtime family.

| Package | Version | Direct consumers | Purpose | Licence | Selection rationale |
|---|---:|---|---|---|---|
| Microsoft.Extensions.Hosting | 10.0.10 | QuietShield.App; QuietShield.Service | Microsoft DI, structured logging, configuration, application lifetime, hosted services, and cancellation | MIT | Required by the requested DI/logging architecture and service foundation; matches the installed stable worker template. |
| MSTest | 4.0.2 | QuietShield.Core.Tests; QuietShield.Windows.Tests; QuietShield.Architecture.Tests | Test framework, adapter, and SDK integration | MIT | Microsoft-supported stable test stack emitted by the installed .NET 10 template. |

The .NET 10 runtime, WPF, BCL, and Windows Desktop targeting packs are framework dependencies rather than NuGet package selections in this repository.

No package is included merely for syntax reduction or convenience. MVVM primitives, architecture checks, and read-only discovery are implemented with framework APIs to keep the dependency surface small.
