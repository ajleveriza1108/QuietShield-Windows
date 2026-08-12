# Phase 12 Self-Contained Beta Installer Report

Status: **Static package milestone passed**

Branch:

`feature/phase-12-self-contained-beta-installer`

Source parent:

`3ae8b328aaa40cb3b037a56ce59bce649a26ba90`

The compiled artifact was produced from the validated Phase 12 source and has not been executed.

## Installer technology

Inno Setup 6 was selected because the repository had no existing packaging stack, it provides the required normal Windows UAC boundary, stable upgrade identity, file rollback/uninstall support, compression, and a future signing interface without introducing a large packaging framework.

Installer upgrade identity:

`{6D13D40D-0A66-49F7-A422-235A2B89DA61}`

## Package architecture

- Platform: Windows 11 x64
- Version: `0.12.0-beta.1`
- Authoritative version source: `Directory.Build.props`
- Desktop payload: .NET 10 WPF, `win-x64`, self-contained
- Service payload: .NET 10 Windows service, `win-x64`, self-contained
- Included runtime: Microsoft.NETCore.App `10.0.11`; desktop also includes Microsoft.WindowsDesktop.App `10.0.11`
- Customer prerequisite: no separate .NET runtime installation
- Excluded: tests, debug symbols, development settings, DNS host/watchdog, connection probe, WDK, video tools, private keys, certificates, and secrets

## Production layout

- Product root: `%ProgramFiles%\QuietShield`
- Desktop: `%ProgramFiles%\QuietShield\App\0.12.0-beta.1`
- Service: `%ProgramFiles%\QuietShield\Service\0.12.0-beta.1`
- Installer lifecycle helpers: `%ProgramFiles%\QuietShield\Installer`
- Machine service state and exact ownership: `%ProgramData%\QuietShield\Service`
- Per-user desktop configuration remains under `%LocalAppData%\QuietShield`

Versioned app/service directories avoid reusing the rehearsal-only `D:\QuietShield\Service` location and support an exact history-preserving upgrade/rollback design. Windows-managed shared components are not relocated.

## Service lifecycle architecture

- The installer uses `PrivilegesRequired=admin`, producing the normal visible Windows installer/UAC boundary.
- The WPF desktop remains `asInvoker` and contains no self-elevation path.
- The exact `QuietShieldService` registration uses a deterministic binary command, automatic delayed start, three 60-second recovery actions, and the production pipe.
- Production IPC is restricted to LocalSystem, Administrators, and the installing user's recorded SID.
- Production authorization independently revalidates the requested absolute executable path, path-derived identity, SHA-256, approved installation root, system/QuietShield exclusion, and reparse-point exclusion.
- Only `Blocked` and `AllowedOnAll` are accepted; network-specific persistent policies remain gated.
- Installation creates no Program Connection Lock rule. Rules remain customer-requested service transactions after exact application validation.
- Upgrade accepts only an exact ownership manifest and keeps the prior version available for rollback.
- Uninstall validates exact service ownership and restores/cleans only immutable recorded QuietShield transactions. It performs no broad Firewall enumeration or cleanup and preserves state evidence.

## DNS and phase boundaries

- DNS activation: absent and still blocked by the Phase 5 loopback orchestration issue
- Adapter DNS changes: none
- WFP changes: none
- Phase 13 licensing: not implemented
- Trial behavior: not implemented
- Phase 14 hardening: not started

## Artifact

Installer:

`D:\Windows Projects\QuietShield-Windows\artifacts\installer\0.12.0-beta.1\package\QuietShield-Windows-x64-0.12.0-beta.1.exe`

- Size: 71,578,576 bytes (68.26 MiB)
- SHA-256: `B065D823F657D3E780795C5D686E7E83B6F7D2638EC3DCA3E8EC04538304ED64`
- App payload files: 430
- Service payload files: 229
- Package inventory files: 669
- Package manifest: `artifacts\installer\0.12.0-beta.1\phase12-package-manifest.json`
- Static validation: `artifacts\installer\0.12.0-beta.1\phase12-validation.json`

## Validation

- Inno Setup compilation: Passed
- Self-contained runtime/file validation: Passed
- Required app/service files: Passed
- Package inventory and SHA-256 validation: Passed
- Version consistency: Passed
- Production path generation: Passed
- Service registration/config generation: Passed
- Fresh/reinstall/upgrade/rollback/uninstall ownership architecture: Passed
- DNS activation absent: Passed
- Installer-time Firewall-rule creation absent: Passed
- Silent self-elevation absent: Passed
- PowerShell 5.1 parsing: Passed, 45 repository scripts
- Automated tests: Passed, 386/386
- Debug x64 build: Passed, 0 warnings/errors
- Release x64 build: Passed, 0 warnings/errors
- Visual Studio 2026 MSBuild Release x64: Passed
- WPF/IPC GUI smoke: Passed
- Protected persistent Windows state: Unchanged
- QuietShield service residue: Zero
- QuietShield Firewall-rule residue: Zero
- `git diff --check`: Passed

## Signing

Signing status: **Not signed**

No production certificate or private key was created, requested, embedded, or committed. The Inno Setup source and build script expose an explicit release-stage signing interface, and static validation requires release signing without treating an unsigned beta-development artifact as signed.

## Final state

- System changes: **NONE**
- Real installer install/upgrade/uninstall rehearsal: **NOT YET ATTEMPTED**
- Installer execution: **PROHIBITED until a new explicit controlled-rehearsal approval**
- Merge to `main`: Not performed
