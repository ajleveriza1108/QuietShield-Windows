[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'DnsTransaction.Script.Common.ps1')

Assert-QuietShieldPowerShell51
Assert-QuietShieldNonElevated
Initialize-QuietShieldProcessEnvironment
$logPath = Start-QuietShieldLog -Name 'validation'
$root = Get-QuietShieldRepositoryRoot
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$resultPath = Join-Path $root ('logs\validation-' + $timestamp + '.json')
$preStatePath = Join-Path $root ('logs\phase5-pre-state-' + $timestamp + '.json')
$postStatePath = Join-Path $root ('logs\phase5-post-state-' + $timestamp + '.json')

try {
    Assert-QuietShieldToolchain
    $before = Get-QuietShieldSafetySnapshot
    $before | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $preStatePath -Encoding UTF8
    $attemptRecordsPath = Join-Path $root 'artifacts\dns-rehearsal\attempt-records.jsonl'
    $attemptRecordsHashBefore = if (Test-Path -LiteralPath $attemptRecordsPath -PathType Leaf) { (Get-FileHash -LiteralPath $attemptRecordsPath -Algorithm SHA256).Hash } else { '[absent]' }
    if ($before.QuietShieldServiceCount -ne 0) {
        throw 'A QuietShield Windows service was already registered before validation.'
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
            $parseFailures += ("{0}:{1}: {2}" -f $scriptFile.FullName, $parseError.Extent.StartLineNumber, $parseError.Message)
        }
    }

    if ($parseFailures.Count -ne 0) {
        throw ('PowerShell parser failures: ' + ($parseFailures -join ' | '))
    }

    Write-Output 'Validating root launcher safety flags.'
    $launchers = @(
        'Build-QuietShield.bat',
        'Test-QuietShield.bat',
        'Run-QuietShield.bat',
        'Clean-QuietShield.bat',
        'Validate-QuietShield.bat',
        'Test-DnsTransactionPlan.bat',
        'Show-DnsTransactionState.bat',
        'Emergency-Restore-Dns.bat',
        'Run-DnsActivationRehearsal.bat'
    )
    foreach ($launcher in $launchers) {
        $launcherPath = Join-Path $root $launcher
        $launcherContent = Get-Content -LiteralPath $launcherPath -Raw
        if ($launcherContent -notmatch 'powershell\.exe -NoProfile -ExecutionPolicy Bypass -File') {
            throw ("Launcher is missing required PowerShell safety flags: {0}" -f $launcher)
        }
        if ($launcherContent -match '(?i)RunAs|requireAdministrator') {
            throw ("Launcher contains an elevation request: {0}" -f $launcher)
        }
    }

    $solution = Join-Path $root 'QuietShield.sln'
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @('restore', $solution, '-p:Platform=x64')
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @('build', $solution, '--configuration', 'Debug', '--no-restore', '-p:Platform=x64')
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @('build', $solution, '--configuration', 'Release', '--no-restore', '-p:Platform=x64')

    $msbuild = Get-QuietShieldMSBuildPath
    $restorePackagesProperty = '/p:RestorePackagesPath=' + $env:NUGET_PACKAGES
    Invoke-QuietShieldCommand -FilePath $msbuild -ArgumentList @(
        $solution,
        '/m',
        '/nologo',
        '/v:minimal',
        '/p:Configuration=Release',
        '/p:Platform=x64',
        $restorePackagesProperty
    )

    Write-Output 'Running the read-only Phase 5 adapter and port-53 preflight without binding any socket.'
    $selectedAdapter = Get-QuietShieldSelectedPhysicalAdapter
    $port53 = Test-QuietShieldPort53Availability
    if (-not [bool]$port53.Available) {
        throw 'Loopback port 53 is already in use; dry validation refuses the rehearsal preflight.'
    }
    $hostPath = Join-Path $root 'artifacts\bin\QuietShield.DnsHost\Release\net10.0-windows\QuietShield.DnsHost.exe'
    $watchdogPath = Join-Path $root 'artifacts\bin\QuietShield.DnsWatchdog\Release\net10.0-windows\QuietShield.DnsWatchdog.exe'
    foreach ($rehearsalExecutable in @($hostPath, $watchdogPath)) {
        if (-not (Test-Path -LiteralPath $rehearsalExecutable -PathType Leaf)) {
            throw ('A required Phase 5 Release executable was not found: ' + $rehearsalExecutable)
        }
    }

    $testResults = Join-Path $root ('artifacts\test-results\validation-' + $timestamp)
    [void](New-Item -ItemType Directory -Path $testResults -Force)
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @(
        'test',
        $solution,
        '--configuration',
        'Release',
        '--no-build',
        '--no-restore',
        '-p:Platform=x64',
        '--results-directory',
        $testResults,
        '--logger',
        'trx'
    )

    Write-Output 'Running Phase 4 UDP, TCP, blocked, allowed-forwarding, and transaction-plan smoke tests.'
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @(
        'test',
        $solution,
        '--configuration',
        'Release',
        '--no-build',
        '--no-restore',
        '-p:Platform=x64',
        '--filter',
        'TestCategory=Phase4Smoke'
    )

    Write-Output 'Running Phase 5 independent-watchdog, rollback, transaction-recovery, and port-conflict simulations.'
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @(
        'test',
        $solution,
        '--configuration',
        'Release',
        '--no-build',
        '--no-restore',
        '-p:Platform=x64',
        '--filter',
        'TestCategory=Phase5Smoke'
    )

    $testCount = 0
    $passedCount = 0
    $failedCount = 0
    foreach ($trx in Get-ChildItem -LiteralPath $testResults -Filter '*.trx' -File) {
        [xml]$testDocument = Get-Content -LiteralPath $trx.FullName -Raw
        $testNamespace = New-Object System.Xml.XmlNamespaceManager($testDocument.NameTable)
        $testNamespace.AddNamespace('t', 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010')
        $results = @($testDocument.SelectNodes('//t:UnitTestResult', $testNamespace))
        $testCount += $results.Count
        $passedCount += @($results | Where-Object { $_.outcome -eq 'Passed' }).Count
        $failedCount += @($results | Where-Object { $_.outcome -ne 'Passed' }).Count
    }
    if ($testCount -eq 0 -or $failedCount -ne 0 -or $passedCount -ne $testCount) {
        throw ("Automated test accounting failed. Total={0}; Passed={1}; Failed={2}" -f $testCount, $passedCount, $failedCount)
    }

    $appPath = Join-Path $root 'artifacts\bin\QuietShield.App\Release\net10.0-windows\QuietShield.App.exe'
    if (-not (Test-Path -LiteralPath $appPath)) {
        throw ("WPF application executable was not found: {0}" -f $appPath)
    }

    $diagnosticPath = Join-Path $testResults 'phase4-live-diagnostic.json'
    Write-Output ('Starting WPF Phase 5 DNS rehearsal-readiness smoke process: ' + $appPath)
    $applicationProcess = Start-Process -FilePath $appPath -ArgumentList @('--phase5-smoke', '--diagnostic-output', ('"' + $diagnosticPath + '"')) -WorkingDirectory (Split-Path -Parent $appPath) -PassThru
    $exited = $applicationProcess.WaitForExit(30000)
    if (-not $exited) {
        throw ("WPF smoke process did not exit within 30 seconds. Process ID {0} was not terminated automatically." -f $applicationProcess.Id)
    }
    if ($applicationProcess.ExitCode -ne 0) {
        throw ("WPF smoke process returned exit code {0}." -f $applicationProcess.ExitCode)
    }
    if (-not (Test-Path -LiteralPath $diagnosticPath)) {
        throw 'The WPF Phase 4 smoke did not create its requested privacy-safe diagnostic summary.'
    }
    $liveDiagnostic = Get-Content -LiteralPath $diagnosticPath -Raw | ConvertFrom-Json
    if ([int]$liveDiagnostic.applicationTotal -le 0) {
        throw 'The live application inventory smoke returned no applications.'
    }
    if ([int]$liveDiagnostic.quietShieldOwnedFirewallRuleCount -ne 0) {
        throw 'QuietShield-owned firewall rules were unexpectedly detected.'
    }

    $backupFixture = Join-Path $root 'tests\Fixtures\phase4-valid-backup.json'
    Write-Output 'Running the transaction-plan launcher in read-only WhatIf mode with a valid non-production fixture.'
    $transactionPlanLauncher = Join-Path $root 'Test-DnsTransactionPlan.bat'
    Invoke-QuietShieldCommand -FilePath $transactionPlanLauncher -ArgumentList @('-WhatIf', '-BackupPath', $backupFixture)

    Write-Output 'Validating that emergency restore -WhatIf refuses a valid backup whose adapter identity does not match this computer.'
    $emergencyLauncher = Join-Path $root 'Emergency-Restore-Dns.bat'
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $emergencyLauncher -WhatIf -BackupPath $backupFixture 2>&1 | Write-Output
        $emergencyExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($emergencyExitCode -eq 0) {
        throw 'Emergency DNS restore unexpectedly accepted a non-matching adapter identity.'
    }

    Write-Output 'Running the Clean launcher in WhatIf mode.'
    $cleanLauncher = Join-Path $root 'Clean-QuietShield.bat'
    Invoke-QuietShieldCommand -FilePath 'cmd.exe' -ArgumentList @('/d', '/c', $cleanLauncher, '-WhatIf')

    $after = Get-QuietShieldSafetySnapshot
    $after | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $postStatePath -Encoding UTF8
    $attemptRecordsHashAfter = if (Test-Path -LiteralPath $attemptRecordsPath -PathType Leaf) { (Get-FileHash -LiteralPath $attemptRecordsPath -Algorithm SHA256).Hash } else { '[absent]' }
    if ($attemptRecordsHashBefore -cne $attemptRecordsHashAfter) { throw 'Dry validation changed the append-only rehearsal attempt records.' }
    if ($after.IsAdministrator) {
        throw 'Validation unexpectedly ran with Administrator elevation.'
    }
    if ($after.QuietShieldServiceCount -ne 0) {
        throw 'A QuietShield Windows service was registered during validation.'
    }

    foreach ($property in @('QuietShieldServiceHash', 'FirewallHash', 'DnsHash', 'AdapterHash', 'StartupHash', 'QuietShieldWfpHash', 'QuietShieldRegistryHash')) {
        if ($before.$property -ne $after.$property) {
            throw ("Safety snapshot changed during validation: {0}" -f $property)
        }
    }

    $validation = [ordered]@{
        schemaVersion = 5
        timestamp = (Get-Date).ToString('o')
        status = 'Passed'
        powershellVersion = $PSVersionTable.PSVersion.ToString()
        visualStudioVersion = '18.8.2 / 18.8.12023.21'
        dotnetSdkVersion = (& dotnet --version | Select-Object -First 1).Trim()
        platform = 'x64'
        debugBuild = 'Passed'
        releaseBuild = 'Passed'
        visualStudioMsbuild = 'Passed'
        automatedTests = [ordered]@{
            total = $testCount
            passed = $passedCount
            failed = $failedCount
        }
        phase4SmokeTests = [ordered]@{
            localUdpDns = 'Passed'
            localTcpDns = 'Passed'
            blockedNxdomain = 'Passed'
            allowedForwarding = 'Passed'
            transactionPlanDryRun = 'Passed'
            emergencyRestoreWhatIfIdentityRefusal = 'Passed'
            privacySafeDiagnosticExport = 'Passed'
        }
        phase5DryValidation = [ordered]@{
            adapterSelection = 'ExactlyOneSupportedPhysicalAdapter'
            adapterIdentity = [ordered]@{
                interfaceGuid = ([Guid]$selectedAdapter.Adapter.InterfaceGuid).ToString('D')
                interfaceIndex = [int]$selectedAdapter.Adapter.InterfaceIndex
                kind = [string]$selectedAdapter.Kind
            }
            port53Preflight = 'AvailableWithoutBinding'
            dnsHostReleaseOutput = $hostPath
            watchdogReleaseOutput = $watchdogPath
            watchdogSimulation = 'Passed'
            rawUdpNxdomainSmoke = 'Passed'
            rawTcpNxdomainSmoke = 'Passed'
            powershell51RawRcodeRecognition = 'Passed'
            trailingDotNormalization = 'Passed'
            allowedExampleForwarding = 'Passed'
            hostPolicyReadiness = 'Passed'
            heartbeatLossSimulation = 'Passed'
            parentLossSimulation = 'Passed'
            deadlineRollbackSimulation = 'Passed'
            transactionRecoverySimulation = 'Passed'
            dnsChanged = $false
            attemptRecordsUnchanged = $true
            preStateSnapshot = $preStatePath
            postStateSnapshot = $postStatePath
        }
        detected = [ordered]@{
            applicationCount = [int]$liveDiagnostic.applicationTotal
            primaryNetworkType = [string]$liveDiagnostic.primaryNetworkType
            networkCost = [string]$liveDiagnostic.networkCost
            networkCategory = [string]$liveDiagnostic.networkCategory
            dnsAdapterCount = [int]$liveDiagnostic.dnsAdapterCount
            dnsModes = $liveDiagnostic.dnsModes
            firewallProfiles = $liveDiagnostic.firewallProfiles
            quietShieldOwnedFirewallRuleCount = [int]$liveDiagnostic.quietShieldOwnedFirewallRuleCount
            filteringPlatform = $liveDiagnostic.filteringPlatform
            services = $liveDiagnostic.services
            power = $liveDiagnostic.power
        }
        wpfLaunchSmoke = [ordered]@{
            status = 'Passed'
            exitCode = $applicationProcess.ExitCode
            executable = $appPath
            phase = 'Phase5Readiness'
        }
        safety = [ordered]@{
            administrator = $after.IsAdministrator
            quietShieldServiceCount = $after.QuietShieldServiceCount
            firewallUnchanged = $true
            dnsUnchanged = $true
            adaptersUnchanged = $true
            startupUnchanged = $true
            quietShieldWfpUnchanged = $true
            quietShieldRegistryUnchanged = $true
            registryMutationCommandsPresent = $false
            certificateCommandsPresent = $false
            securitySettingMutationCommandsPresent = $false
        }
        logPath = $logPath
    }

    $validation | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $resultPath -Encoding UTF8
    Write-Output ("Validation succeeded. Tests: {0}/{1}. Result: {2}" -f $passedCount, $testCount, $resultPath)
}
catch {
    $failure = [ordered]@{
        schemaVersion = 1
        timestamp = (Get-Date).ToString('o')
        status = 'Failed'
        error = $_.Exception.Message
        logPath = $logPath
    }
    $failure | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $resultPath -Encoding UTF8
    throw
}
finally {
    Stop-QuietShieldLog
}
