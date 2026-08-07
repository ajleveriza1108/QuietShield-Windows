[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ServiceActivation.Script.Common.ps1')

Assert-QuietShieldPowerShell51
Assert-QuietShieldNonElevated
Initialize-QuietShieldProcessEnvironment

$root = Get-QuietShieldRepositoryRoot
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logPath = Start-QuietShieldLog -Name 'phase11b-validation'
$resultPath = Join-Path $root ('logs\phase11b-validation-' + $timestamp + '.json')
$beforePath = Join-Path $root ('logs\phase11b-protected-before-' + $timestamp + '.json')
$afterPath = Join-Path $root ('logs\phase11b-protected-after-' + $timestamp + '.json')
$designReportPath = Join-Path $root 'PHASE-11B-TARGET-AUTHORIZATION-DESIGN.md'
$phase10BReportPath = Join-Path $root 'PHASE-10B-SERVICE-ACTIVATION-REPORT.md'
$phase11AReportPath = Join-Path $root 'PHASE-11-INTEGRATION-REPORT.md'
$phase10BHashBefore = (Get-FileHash -LiteralPath $phase10BReportPath -Algorithm SHA256).Hash
$phase11AHashBefore = (Get-FileHash -LiteralPath $phase11AReportPath -Algorithm SHA256).Hash
$targetDirectory = Join-Path $root 'artifacts\phase11b\dry-target'

try {
    $before = Get-QuietShieldSafetySnapshot
    $before | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $beforePath -Encoding UTF8

    if ([int]$before.QuietShieldServiceCount -ne 0) {
        throw 'A QuietShield service is registered before Phase 11B dry validation.'
    }

    if (@(Get-NetFirewallRule -Name 'QuietShield.ProgramLock.*' -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'QuietShield Program Lock rules exist before Phase 11B dry validation.'
    }

    Write-Output 'Parsing every repository PowerShell script with Windows PowerShell 5.1.'
    $parseFailures = @()

    foreach ($scriptFile in Get-ChildItem -LiteralPath (Join-Path $root 'scripts') -Filter '*.ps1' -File -Recurse) {
        $tokens = $null
        $errors = $null

        [void][System.Management.Automation.Language.Parser]::ParseFile(
            $scriptFile.FullName,
            [ref]$tokens,
            [ref]$errors)

        foreach ($parseError in @($errors)) {
            $parseFailures += (
                '{0}:{1}: {2}' -f
                $scriptFile.FullName,
                $parseError.Extent.StartLineNumber,
                $parseError.Message)
        }
    }

    if ($parseFailures.Count -ne 0) {
        throw ('PowerShell parser failures: ' + ($parseFailures -join ' | '))
    }

    $solution = Join-Path $root 'QuietShield.sln'

    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @(
        'restore',
        $solution,
        '-p:Platform=x64')

    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @(
        'build',
        $solution,
        '-c',
        'Debug',
        '--no-restore',
        '-p:Platform=x64')

    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @(
        'build',
        $solution,
        '-c',
        'Release',
        '--no-restore',
        '-p:Platform=x64')

    $msbuild = Get-QuietShieldMSBuildPath

    Invoke-QuietShieldCommand -FilePath $msbuild -ArgumentList @(
        $solution,
        '/m',
        '/nologo',
        '/v:minimal',
        '/p:Configuration=Release',
        '/p:Platform=x64',
        ('/p:RestorePackagesPath=' + $env:NUGET_PACKAGES))

    $testResults = Join-Path $root ('artifacts\test-results\phase11b-' + $timestamp)
    New-Item -ItemType Directory -Path $testResults -Force | Out-Null

    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @(
        'test',
        $solution,
        '-c',
        'Release',
        '--no-build',
        '--no-restore',
        '-p:Platform=x64',
        '--results-directory',
        $testResults,
        '--logger',
        'trx')

    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @(
        'test',
        (Join-Path $root 'tests\QuietShield.Architecture.Tests\QuietShield.Architecture.Tests.csproj'),
        '-c',
        'Release',
        '--no-build',
        '--no-restore',
        '--filter',
        'FullyQualifiedName~Phase11BProgramTargetAuthorizationTests')

    Write-Output 'Building the exact Release service package.'
    & (Join-Path $PSScriptRoot 'New-QuietShieldServicePackage.ps1') | Write-Output

    # Do not infer package success by reparsing mixed console/build output.
    # Validate the generated package directly with the same exact package
    # validator used by installation and the service lifecycle.
    $packageRoot = Join-Path $root 'artifacts\service-package\Release'
    $packageResult = Test-QuietShieldServicePackage -PackageRoot $packageRoot

    if ($null -eq $packageResult -or
        [string]::IsNullOrWhiteSpace([string]$packageResult.PayloadSha256) -or
        -not (Test-Path -LiteralPath ([string]$packageResult.ExecutablePath) -PathType Leaf)) {
        throw 'The Phase 11B Release service package did not pass direct on-disk validation.'
    }

    if (Test-Path -LiteralPath $targetDirectory) {
        Remove-Item -LiteralPath $targetDirectory -Recurse -Force
    }

    New-Item -ItemType Directory -Path $targetDirectory -Force | Out-Null

    $probePath = Join-Path $root 'artifacts\bin\QuietShield.ConnectionProbe\x64\Release\net10.0\QuietShield.ConnectionProbe.exe'
    if (-not (Test-Path -LiteralPath $probePath -PathType Leaf)) {
        throw 'The validated Release connection test executable is missing.'
    }

    $targetPath = Join-Path $targetDirectory 'QuietShield.CustomerProgramTarget.exe'
    Copy-Item -LiteralPath $probePath -Destination $targetPath -Force

    $targetIdentity = Get-QuietShieldApprovedProgramIdentity -Path $targetPath

    if ($targetIdentity -notmatch '\Awindows-exe:[0-9a-f]{32}\z') {
        throw 'The path-derived approved program identity is invalid.'
    }

    if ($targetIdentity -ceq 'quietshield.connection-probe') {
        throw 'The generalized target identity unexpectedly equals the legacy probe identity.'
    }

    Write-Output 'Running exact service installation planning with the generalized approved program target.'
    $dryRehearsalId = [Guid]'11b00000-0000-4000-8000-000000000001'

    $installPlanOutput = @(
        & (Join-Path $PSScriptRoot 'Install-QuietShieldService.ps1') `
            -ApprovedRehearsalId $dryRehearsalId `
            -AuthorizedProgramPath $targetPath `
            -WhatIf
    )

    $installPlan = (($installPlanOutput -join "`n") | ConvertFrom-Json)

    if ([string]$installPlan.status -cne 'InstallationPlanValidated') {
        throw 'The generalized service installation plan did not validate.'
    }

    if ([bool]$installPlan.modifyingCommandInvoked) {
        throw 'The generalized service installation dry run unexpectedly reported a modifying command.'
    }

    if ([IO.Path]::GetFullPath([string]$installPlan.authorizedProgramPath) -cne [IO.Path]::GetFullPath($targetPath)) {
        throw 'The installation plan did not bind the exact authorized program path.'
    }

    if ([string]$installPlan.authorizedStableApplicationIdentity -cne $targetIdentity) {
        throw 'The installation plan did not bind the path-derived stable application identity.'
    }

    Remove-Item -LiteralPath $targetDirectory -Recurse -Force

    $after = Get-QuietShieldSafetySnapshot
    $after | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $afterPath -Encoding UTF8

    $comparison = Compare-QuietShieldSafetySnapshots -Before $before -After $after
    if (-not [bool]$comparison.PersistentMatch) {
        throw ('Protected Windows state changed during Phase 11B dry validation: ' +
            (@($comparison.PersistentDifferences) -join ', '))
    }

    if ([int]$after.QuietShieldServiceCount -ne 0) {
        throw 'A QuietShield service exists after Phase 11B dry validation.'
    }

    if (@(Get-NetFirewallRule -Name 'QuietShield.ProgramLock.*' -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'QuietShield Program Lock rules exist after Phase 11B dry validation.'
    }

    if ((Get-FileHash -LiteralPath $phase10BReportPath -Algorithm SHA256).Hash -cne $phase10BHashBefore) {
        throw 'The finalized Phase 10B report changed during Phase 11B.'
    }

    if ((Get-FileHash -LiteralPath $phase11AReportPath -Algorithm SHA256).Hash -cne $phase11AHashBefore) {
        throw 'The Phase 11A integration report changed during Phase 11B.'
    }

    $designReport = @"
# Phase 11B Controlled Program Target Authorization Design

Status: **Passed**

## Outcome

Phase 11B removes the service coordinator's hard-coded dependency on the literal `quietshield.connection-probe` application identity while preserving exact activation binding.

The generalized authorization remains limited to one explicitly approved executable per controlled activation:

- exact absolute program path
- exact SHA-256 of that executable
- deterministic path-derived stable application identity
- exact approved rehearsal ID
- Blocked or AllowedOnAll only
- exact deterministic `QuietShield.ProgramLock.<id>` rule ownership
- LocalSystem-only real Firewall backend
- immutable transaction record, backup, verification, rollback, and last-known-good recovery

The existing Phase 10B probe identity remains accepted only as a backwards-compatible legacy identity when the activated executable is exactly `QuietShield.ConnectionProbe.exe`.

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
"@

    $designReport | Set-Content -LiteralPath $designReportPath -Encoding UTF8

    [pscustomobject][ordered]@{
        schemaVersion = 1
        phase = 'Phase11BControlledProgramTargetAuthorization'
        status = 'Passed'
        generalizedIdentity = $targetIdentity
        servicePackage = 'Passed'
        installWhatIf = 'Passed'
        fullTestSuite = 'Passed'
        serviceCountAfter = [int]$after.QuietShieldServiceCount
        programLockRuleCountAfter = 0
        protectedWindowsState = 'Unchanged'
        customerEnforcementControls = 'Absent'
        dnsActivation = 'Not attempted'
        designReport = $designReportPath
        log = $logPath
    } | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $resultPath -Encoding UTF8

    Get-Content -LiteralPath $resultPath -Raw
}
finally {
    if (Test-Path -LiteralPath $targetDirectory) {
        Remove-Item -LiteralPath $targetDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }

    Stop-QuietShieldLog
}
