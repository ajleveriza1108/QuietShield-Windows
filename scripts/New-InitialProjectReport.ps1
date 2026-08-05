[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')

Assert-QuietShieldPowerShell51
Assert-QuietShieldNonElevated
$logPath = Start-QuietShieldLog -Name 'initial-project-report'

try {
    $root = Get-QuietShieldRepositoryRoot
    $validationFile = Get-ChildItem -LiteralPath (Join-Path $root 'logs') -Filter 'validation-*.json' -File |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $validationFile) {
        throw 'No final validation JSON was found.'
    }

    $validation = Get-Content -LiteralPath $validationFile.FullName -Raw | ConvertFrom-Json
    if ($validation.status -ne 'Passed') {
        throw 'The latest validation did not pass.'
    }

    $gitArguments = @('-c', ('safe.directory=' + $root), '-C', $root)
    $commitOutput = @(& git @gitArguments rev-parse HEAD 2>&1)
    $commitExitCode = $LASTEXITCODE
    $commitHash = ([string]($commitOutput | Select-Object -First 1)).Trim()
    if ($commitExitCode -ne 0 -or $commitHash -notmatch '^[0-9a-f]{40}$') {
        throw 'A valid local Git commit hash was not found.'
    }

    $remoteLines = @(& git @gitArguments remote)
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to verify Git remotes.'
    }
    if ($remoteLines.Count -ne 0) {
        throw 'The repository unexpectedly has a Git remote.'
    }

    $instance = Get-QuietShieldVisualStudio2026Instance
    $msbuild = Get-QuietShieldMSBuildPath
    $msbuildVersion = (& $msbuild -version -nologo | Select-Object -Last 1).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to record the Visual Studio 2026 MSBuild version.'
    }

    $dotnetSdk = (& dotnet --version | Select-Object -First 1).Trim()
    $gitVersion = (& git --version | Select-Object -First 1).Trim()
    $reportPath = Join-Path $root 'INITIAL-PROJECT-REPORT.md'
    $completedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')

    $report = @'
# QuietShield Windows initial project report

Completed: __COMPLETED_AT__  
Status: **Foundation created, validated, and locally committed**

## Exact solution structure

```text
QuietShield-Windows/
|-- QuietShield.sln
|-- Directory.Build.props
|-- Directory.Packages.props
|-- global.json
|-- src/
|   |-- QuietShield.App/
|   |-- QuietShield.Core/
|   |-- QuietShield.Windows/
|   |-- QuietShield.Service/
|   `-- QuietShield.Licensing/
|-- tests/
|   |-- QuietShield.Core.Tests/
|   |-- QuietShield.Windows.Tests/
|   `-- QuietShield.Architecture.Tests/
|-- scripts/
|-- installer/
|-- docs/
|-- logs/
`-- artifacts/
```

The authoritative repository path is `__ROOT__`.

## SDK and tool versions

| Tool | Validated version |
|---|---|
| Visual Studio Community 2026 | 18.8.2 / __VS_INSTALLATION_VERSION__ |
| Visual Studio 2026 MSBuild | __MSBUILD_VERSION__ |
| .NET SDK | __DOTNET_SDK__ |
| Windows Desktop target/runtime | .NET 10 / 10.0.10 |
| Windows PowerShell | __POWERSHELL_VERSION__ |
| Git | __GIT_VERSION__ |
| Platform | Windows 11 x64 |

Visual Studio 2022 and Visual Studio 2026 remained installed exactly as previously validated. No development software setup, update, repair, removal, or installation ran.

## Package inventory and licences

| Package | Version | Purpose | Licence | Projects |
|---|---:|---|---|---|
| Microsoft.Extensions.Hosting | 10.0.10 | DI, structured logging, host lifetime, cancellation | MIT | QuietShield.App; QuietShield.Service |
| MSTest | 4.0.2 | Automated test framework and runner | MIT | All three test projects |

No preview package, third-party networking package, Python, Node.js, Java, Electron, WebView2, SQLite, WDK, or driver dependency is present.

## Build and test results

- Debug x64 build: **__DEBUG_BUILD__**
- Release x64 build: **__RELEASE_BUILD__**
- Visual Studio 2026 MSBuild Release x64 build: **__MSBUILD_RESULT__**
- Automated tests: **__TESTS_PASSED__ passed / __TESTS_TOTAL__ total / __TESTS_FAILED__ failed**
- WPF application launch smoke: **__WPF_STATUS__**, exit code __WPF_EXIT_CODE__
- PowerShell 5.1 parser validation: **Passed for every script**
- Root launcher validation: **Passed**, including Clean in `-WhatIf` mode

## Safety validation

- Ran without Administrator elevation: **Yes**
- Windows service registered: **No**
- Firewall snapshot changed: **No**
- DNS snapshot changed: **No**
- Adapter snapshot changed: **No**
- Startup snapshot changed: **No**
- Registry mutation command present: **No**
- Certificate command present: **No**
- Security-setting mutation command present: **No**
- Existing source project or other repository touched: **No**
- Git remote added or push performed: **No**

The WPF application clearly reports Foundation Mode and inactive protection. It displays no fabricated activity or protection statistics. The background-service executable was compiled and cancellation-tested but was not installed or registered.

## Local Git commit

- Commit: `__COMMIT_HASH__`
- Remote: none
- Push: not performed

This report is generated after the commit so it can contain that commit's hash; it is intentionally a local ignored validation artifact.

## Known limitations

- No protection engine or enforcement is active.
- Program inventory and Store identity discovery are placeholders.
- Metered connection cost, Firewall, WFP, service, startup, notification, power, and tray integrations are explicitly deferred.
- Licensing has no server communication, token storage implementation, endpoint, credential, or device-fingerprint algorithm.
- No DNS protection, Program Connection Lock enforcement, Private Browser, File Safety engine, updater, installer, WDK component, or driver exists.
- Read-only network discovery can report only what framework APIs expose and identifies metered cost as unknown.

## Exact recommended next phase

Proceed only with a separately approved **read-only inventory and policy-simulation phase**: add privacy-redacted installed-program and Store-identity discovery, richer read-only network cost detection, deterministic in-memory policy evaluation, localization resources, and accessibility refinement. Continue to forbid Firewall, DNS, adapter, service, startup, registry, certificate, WFP, licensing-server, browser, installer, and kernel changes during that phase.

Validation evidence: `__VALIDATION_FILE__`  
Validation log: `__VALIDATION_LOG__`  
Report-generation log: `__REPORT_LOG__`
'@

    $report = $report.Replace('__COMPLETED_AT__', $completedAt)
    $report = $report.Replace('__ROOT__', $root)
    $report = $report.Replace('__VS_INSTALLATION_VERSION__', [string]$instance.installationVersion)
    $report = $report.Replace('__MSBUILD_VERSION__', $msbuildVersion)
    $report = $report.Replace('__DOTNET_SDK__', $dotnetSdk)
    $report = $report.Replace('__POWERSHELL_VERSION__', $PSVersionTable.PSVersion.ToString())
    $report = $report.Replace('__GIT_VERSION__', $gitVersion)
    $report = $report.Replace('__DEBUG_BUILD__', [string]$validation.debugBuild)
    $report = $report.Replace('__RELEASE_BUILD__', [string]$validation.releaseBuild)
    $report = $report.Replace('__MSBUILD_RESULT__', [string]$validation.visualStudioMsbuild)
    $report = $report.Replace('__TESTS_PASSED__', [string]$validation.automatedTests.passed)
    $report = $report.Replace('__TESTS_TOTAL__', [string]$validation.automatedTests.total)
    $report = $report.Replace('__TESTS_FAILED__', [string]$validation.automatedTests.failed)
    $report = $report.Replace('__WPF_STATUS__', [string]$validation.wpfLaunchSmoke.status)
    $report = $report.Replace('__WPF_EXIT_CODE__', [string]$validation.wpfLaunchSmoke.exitCode)
    $report = $report.Replace('__COMMIT_HASH__', $commitHash)
    $report = $report.Replace('__VALIDATION_FILE__', $validationFile.FullName)
    $report = $report.Replace('__VALIDATION_LOG__', [string]$validation.logPath)
    $report = $report.Replace('__REPORT_LOG__', $logPath)

    Set-Content -LiteralPath $reportPath -Value $report -Encoding UTF8
    Write-Output ('Initial project report created: ' + $reportPath)
}
finally {
    Stop-QuietShieldLog
}
