[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')

Assert-QuietShieldPowerShell51
Assert-QuietShieldNonElevated
Initialize-QuietShieldProcessEnvironment

$root = Get-QuietShieldRepositoryRoot
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logPath = Start-QuietShieldLog -Name 'phase11-validation'
$resultPath = Join-Path $root ('logs\phase11-validation-' + $timestamp + '.json')
$beforePath = Join-Path $root ('logs\phase11-protected-before-' + $timestamp + '.json')
$afterPath = Join-Path $root ('logs\phase11-protected-after-' + $timestamp + '.json')
$reportPath = Join-Path $root 'PHASE-11-INTEGRATION-REPORT.md'
$phase10BReportPath = Join-Path $root 'PHASE-10B-SERVICE-ACTIVATION-REPORT.md'
$phase10BReportHashBefore = (Get-FileHash -LiteralPath $phase10BReportPath -Algorithm SHA256).Hash

$serviceProcess = $null

try {
    $before = Get-QuietShieldSafetySnapshot
    $before | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $beforePath -Encoding UTF8

    if ([int]$before.QuietShieldServiceCount -ne 0) {
        throw 'A QuietShield service is registered before the non-elevated Phase 11A validation.'
    }

    $beforeRuleCount = @(Get-NetFirewallRule -Name 'QuietShield.ProgramLock.*' -ErrorAction SilentlyContinue).Count
    if ($beforeRuleCount -ne 0) {
        throw 'QuietShield Program Lock rules exist before the non-elevated Phase 11A validation.'
    }

    Write-Output 'Parsing every PowerShell script with the Windows PowerShell 5.1 parser.'
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

    Write-Output 'Restoring and building QuietShield Windows.'
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

    $testResults = Join-Path $root ('artifacts\test-results\phase11-' + $timestamp)
    New-Item -ItemType Directory -Path $testResults -Force | Out-Null

    Write-Output 'Running the complete automated test suite.'
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

    Write-Output 'Running the Phase 11 integration safety regressions directly.'
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @(
        'test',
        (Join-Path $root 'tests\QuietShield.Architecture.Tests\QuietShield.Architecture.Tests.csproj'),
        '-c',
        'Release',
        '--no-build',
        '--no-restore',
        '--filter',
        'FullyQualifiedName~Phase11IntegrationSafetyTests')

    $guiDirectory = Join-Path $root ('artifacts\phase11\gui-' + $timestamp)
    New-Item -ItemType Directory -Path $guiDirectory -Force | Out-Null

    $pipeName = 'QuietShield.Service.Phase11.' + [Guid]::NewGuid().ToString('N')
    $servicePath = Join-Path $root 'artifacts\bin\QuietShield.Service\Release\net10.0-windows\QuietShield.Service.exe'
    $appPath = Join-Path $root 'artifacts\bin\QuietShield.App\Release\net10.0-windows\QuietShield.App.exe'
    $guiResultPath = Join-Path $guiDirectory 'gui-validation.json'
    $planPath = Join-Path $guiDirectory 'program-lock-plan.json'
    $stateRoot = Join-Path $guiDirectory 'diagnostic-service-state'
    $serviceStdout = Join-Path $guiDirectory 'service.stdout.log'
    $serviceStderr = Join-Path $guiDirectory 'service.stderr.log'
    $appStdout = Join-Path $guiDirectory 'app.stdout.log'
    $appStderr = Join-Path $guiDirectory 'app.stderr.log'

    if (-not (Test-Path -LiteralPath $servicePath -PathType Leaf)) {
        throw ('Release service executable not found: ' + $servicePath)
    }

    if (-not (Test-Path -LiteralPath $appPath -PathType Leaf)) {
        throw ('Release WPF executable not found: ' + $appPath)
    }

    Write-Output 'Starting a temporary non-elevated diagnostic service for Phase 11 desktop IPC validation.'
    $serviceArguments = '--diagnostic --pipe-name "{0}" --state-root "{1}" --duration-seconds 30' -f $pipeName, $stateRoot

    $serviceProcess = Start-Process `
        -FilePath $servicePath `
        -ArgumentList $serviceArguments `
        -PassThru `
        -WindowStyle Hidden `
        -RedirectStandardOutput $serviceStdout `
        -RedirectStandardError $serviceStderr

    Start-Sleep -Milliseconds 1200

    if ($serviceProcess.HasExited) {
        throw ('The diagnostic service exited before GUI validation. Exit code: ' + $serviceProcess.ExitCode)
    }

    $appArguments = @(
        '--phase11-smoke',
        '--service-pipe-name',
        ('"' + $pipeName + '"'),
        '--gui-validation-output',
        ('"' + $guiResultPath + '"'),
        '--plan-export-output',
        ('"' + $planPath + '"')
    )

    Write-Output 'Running the Phase 11 WPF integration smoke.'
    $appProcess = Start-Process `
        -FilePath $appPath `
        -ArgumentList $appArguments `
        -PassThru `
        -Wait `
        -WindowStyle Hidden `
        -RedirectStandardOutput $appStdout `
        -RedirectStandardError $appStderr

    if ($appProcess.ExitCode -ne 0) {
        throw ('The Phase 11 WPF smoke failed with exit code ' + $appProcess.ExitCode + '. See ' + $appStderr)
    }

    if (-not (Test-Path -LiteralPath $guiResultPath -PathType Leaf)) {
        throw 'The Phase 11 WPF smoke did not create gui-validation.json.'
    }

    $guiResult = Get-Content -LiteralPath $guiResultPath -Raw | ConvertFrom-Json

    if ([string]$guiResult.Status -cne 'Passed') {
        throw ('Phase 11 GUI validation failed: ' + (@($guiResult.Errors) -join ' | '))
    }

    if (-not [bool]$guiResult.RefreshServiceStatusVisible) {
        throw 'Refresh Service Status was not validated as visible.'
    }

    if (-not [bool]$guiResult.ServiceStatusRefreshSucceeded) {
        throw 'Desktop-to-service status refresh did not pass.'
    }

    if (-not [bool]$guiResult.CustomerEnforcementControlsAbsent) {
        throw 'A customer enforcement control was exposed prematurely.'
    }

    if (-not $serviceProcess.WaitForExit(40000)) {
        throw ('Diagnostic service did not exit within its bounded duration. Process ID requiring review: ' + $serviceProcess.Id)
    }

    $after = Get-QuietShieldSafetySnapshot
    $after | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $afterPath -Encoding UTF8

    $comparison = Compare-QuietShieldSafetySnapshots -Before $before -After $after
    if (-not [bool]$comparison.PersistentMatch) {
        throw ('Protected Windows state changed: ' + (@($comparison.PersistentDifferences) -join ', '))
    }

    if ([int]$after.QuietShieldServiceCount -ne 0) {
        throw 'A QuietShield service remains after Phase 11A validation.'
    }

    $afterRuleCount = @(Get-NetFirewallRule -Name 'QuietShield.ProgramLock.*' -ErrorAction SilentlyContinue).Count
    if ($afterRuleCount -ne 0) {
        throw 'QuietShield Program Lock rules remain after Phase 11A validation.'
    }

    $phase10BReportHashAfter = (Get-FileHash -LiteralPath $phase10BReportPath -Algorithm SHA256).Hash
    if ($phase10BReportHashAfter -cne $phase10BReportHashBefore) {
        throw 'The finalized Phase 10B validation report changed during Phase 11A.'
    }

    $report = @"
# Phase 11A Desktop / Service Integration Report

Status: **Passed**

## Outcome

Phase 11A connects the WPF desktop to the already-validated QuietShield service status path without installing a service or exposing customer enforcement actions.

- Desktop service status refresh: Passed
- Temporary non-elevated diagnostic service IPC: Passed
- Program Connection Lock integration messaging: Passed
- Customer Install/Start/Apply/Enforce/Block Now controls: Absent
- Full automated test suite: Passed
- Release x64 build: Passed
- Visual Studio Release x64 build: Passed
- Responsive WPF Phase 11 smoke: Passed
- QuietShield service count after validation: 0
- QuietShield-owned Firewall rule count after validation: 0
- Protected persistent Windows state: Unchanged
- Finalized Phase 10B report: Unchanged
- DNS activation: Not attempted

## Scope boundary

This is an integration and stabilization step. It does not generalize the controlled Phase 10B probe authorization into customer application enforcement. Customer Blocked / Allowed-on-All activation remains gated for the next separately validated Phase 11 step.
"@

    $report | Set-Content -LiteralPath $reportPath -Encoding UTF8

    $result = [ordered]@{
        schemaVersion = 11
        phase = 'Phase11ADesktopServiceIntegration'
        timestamp = (Get-Date).ToString('o')
        status = 'Passed'
        fullTestSuite = 'Passed'
        debugX64Build = 'Passed'
        releaseX64Build = 'Passed'
        visualStudioReleaseX64Build = 'Passed'
        desktopServiceStatusRefresh = 'Passed'
        phase11GuiSmoke = 'Passed'
        customerEnforcementControls = 'Absent'
        serviceCountAfter = [int]$after.QuietShieldServiceCount
        quietShieldFirewallRuleCountAfter = $afterRuleCount
        persistentWindowsState = 'Unchanged'
        phase10BReport = 'Unchanged'
        dnsActivation = 'Not attempted'
        report = $reportPath
        log = $logPath
    }

    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resultPath -Encoding UTF8
    $result | ConvertTo-Json -Depth 8
}
finally {
    if ($null -ne $serviceProcess) {
        if (-not $serviceProcess.HasExited) {
            Write-Warning ('Temporary diagnostic service is still running and was not force-terminated. Process ID: ' + $serviceProcess.Id)
        }

        $serviceProcess.Dispose()
    }
}
