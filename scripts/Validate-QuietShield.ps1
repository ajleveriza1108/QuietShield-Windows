[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'DnsTransaction.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ProgramLockRehearsal.Script.Common.ps1')

Assert-QuietShieldPowerShell51
Assert-QuietShieldNonElevated
Initialize-QuietShieldProcessEnvironment
$logPath = Start-QuietShieldLog -Name 'validation'
$root = Get-QuietShieldRepositoryRoot
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$resultPath = Join-Path $root ('logs\validation-' + $timestamp + '.json')
$preStatePath = Join-Path $root ('logs\phase9-pre-state-' + $timestamp + '.json')
$postStatePath = Join-Path $root ('logs\phase9-post-state-' + $timestamp + '.json')

try {
    Assert-QuietShieldToolchain
    $before = Get-QuietShieldSafetySnapshot
    $before | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $preStatePath -Encoding UTF8
    $attemptRecordsPath = Join-Path $root 'artifacts\dns-rehearsal\attempt-records.jsonl'
    $attemptRecordsHashBefore = if (Test-Path -LiteralPath $attemptRecordsPath -PathType Leaf) { (Get-FileHash -LiteralPath $attemptRecordsPath -Algorithm SHA256).Hash } else { '[absent]' }
    $firewallAttemptRecordsPath = Join-Path $root 'artifacts\program-lock-rehearsal\attempts.jsonl'
    $firewallAttemptRecordsHashBefore = if (Test-Path -LiteralPath $firewallAttemptRecordsPath -PathType Leaf) { (Get-FileHash -LiteralPath $firewallAttemptRecordsPath -Algorithm SHA256).Hash } else { '[absent]' }
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
        'Run-DnsActivationRehearsal.bat',
        'Test-ProgramLockTransaction.bat',
        'Show-ProgramLockTransactionState.bat',
        'Emergency-Restore-ProgramLock.bat',
        'Run-ProgramLock-Rehearsal.bat',
        'Show-ProgramLock-Rehearsal-State.bat',
        'Emergency-Restore-ProgramLock-Rehearsal.bat'
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

    Write-Output 'Running architecture tests explicitly.'
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @(
        'test',
        (Join-Path $root 'tests\QuietShield.Architecture.Tests\QuietShield.Architecture.Tests.csproj'),
        '--configuration',
        'Release',
        '--no-build',
        '--no-restore'
    )

    Write-Output 'Running the Phase 7 profile, identity, schedule, decision, compatibility, and planner smoke set.'
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @(
        'test',
        $solution,
        '--configuration',
        'Release',
        '--no-build',
        '--no-restore',
        '-p:Platform=x64',
        '--filter',
        'FullyQualifiedName~Phase7'
    )

    Write-Output 'Running the Phase 8 identity, preflight, plan, backup, rollback, recovery, and read-only Windows capability smoke set.'
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @(
        'test',
        $solution,
        '--configuration',
        'Release',
        '--no-build',
        '--no-restore',
        '-p:Platform=x64',
        '--filter',
        'FullyQualifiedName~Phase8'
    )

    Write-Output 'Running the Phase 9 probe, exact-rule identity, watchdog, rollback, concurrency, and duration smoke set.'
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @(
        'test',
        $solution,
        '--configuration',
        'Release',
        '--no-build',
        '--no-restore',
        '-p:Platform=x64',
        '--filter',
        'FullyQualifiedName~Phase9|TestCategory=Phase9Smoke'
    )

    Write-Output 'Running the Phase 9 PowerShell 5.1 watchdog, DateTimeOffset, protected-state, and exact-cleanup simulations.'
    $phase9WatchdogSimulationOutput = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'scripts\Test-ProgramLockWatchdogSimulations.ps1') 2>&1)
    $phase9WatchdogSimulationExitCode = $LASTEXITCODE
    $phase9WatchdogSimulationOutput | Write-Output
    if ($phase9WatchdogSimulationExitCode -ne 0) { throw ('Phase 9 watchdog simulations returned exit code ' + [string]$phase9WatchdogSimulationExitCode) }
    $phase9WatchdogSimulation = ($phase9WatchdogSimulationOutput -join [Environment]::NewLine) | ConvertFrom-Json
    if ([string]$phase9WatchdogSimulation.status -cne 'Passed') { throw 'Phase 9 watchdog simulations did not report Passed.' }

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

    $probePath = Join-Path $root 'artifacts\bin\QuietShield.ConnectionProbe\x64\Release\net10.0\QuietShield.ConnectionProbe.exe'
    if (-not (Test-Path -LiteralPath $probePath -PathType Leaf)) { throw ('The dedicated Phase 9 probe executable was not found: ' + $probePath) }
    $phase9DryStatePath = Join-Path $testResults 'phase9-firewall-dry-state.json'
    Write-Output 'Running the Phase 9 reachable-endpoint probe, transaction dry-run, and watchdog simulation without creating a Firewall rule.'
    $phase9DryOutput = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'scripts\Invoke-ProgramLockFirewallRehearsal.ps1') -DryRun -DurationSeconds 15 -OutputPath $phase9DryStatePath 2>&1
    $phase9DryOutput | Write-Output
    if ($LASTEXITCODE -ne 0) { throw ('Phase 9 dry-run returned exit code ' + [string]$LASTEXITCODE) }
    $phase9DryState = Get-Content -LiteralPath $phase9DryStatePath -Raw | ConvertFrom-Json
    if ([string]$phase9DryState.state -cne 'WatchdogStarted' -or [bool]$phase9DryState.completed -or [int]$phase9DryState.durationSeconds -ne 15) {
        throw 'Phase 9 dry transaction state is invalid.'
    }
    $dryRehearsalRules = @(Get-NetFirewallRule -Name ([string]$phase9DryState.rule.name) -ErrorAction SilentlyContinue)
    if ($dryRehearsalRules.Count -ne 0) {
        throw 'Phase 9 dry validation unexpectedly created its proposed Firewall rule.'
    }
    Write-Output 'Running exact Program Lock rehearsal restore in WhatIf mode.'
    Invoke-QuietShieldCommand -FilePath 'powershell.exe' -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $root 'scripts\Restore-ProgramLockRehearsal.ps1'),
        '-StatePath', $phase9DryStatePath, '-WhatIf'
    )

    $diagnosticPath = Join-Path $testResults 'phase9-live-diagnostic.json'
    $guiValidationPath = Join-Path $testResults 'phase9-gui-validation.json'
    $planExportPath = Join-Path $testResults 'phase9-enforcement-plan.json'
    Write-Output ('Starting WPF Phase 9 rehearsal-status, inherited transaction-plan, responsive, long-text, virtualization, and keyboard smoke process: ' + $appPath)
    $applicationProcess = Start-Process -FilePath $appPath -ArgumentList @(
        '--phase9-smoke',
        '--diagnostic-output',
        ('"' + $diagnosticPath + '"'),
        '--gui-validation-output',
        ('"' + $guiValidationPath + '"'),
        '--plan-export-output',
        ('"' + $planExportPath + '"')
    ) -WorkingDirectory (Split-Path -Parent $appPath) -PassThru
    $exited = $applicationProcess.WaitForExit(30000)
    if (-not $exited) {
        throw ("WPF smoke process did not exit within 30 seconds. Process ID {0} was not terminated automatically." -f $applicationProcess.Id)
    }
    if ($applicationProcess.ExitCode -ne 0) {
        throw ("WPF smoke process returned exit code {0}." -f $applicationProcess.ExitCode)
    }
    if (-not (Test-Path -LiteralPath $diagnosticPath)) {
        throw 'The WPF Phase 9 smoke did not create its requested privacy-safe diagnostic summary.'
    }
    if (-not (Test-Path -LiteralPath $guiValidationPath)) {
        throw 'The WPF Phase 9 smoke did not create its GUI validation result.'
    }
    $liveDiagnostic = Get-Content -LiteralPath $diagnosticPath -Raw | ConvertFrom-Json
    $guiValidation = Get-Content -LiteralPath $guiValidationPath -Raw | ConvertFrom-Json
    if ([int]$liveDiagnostic.applicationTotal -le 0) {
        throw 'The live application inventory smoke returned no applications.'
    }
    if ([int]$liveDiagnostic.quietShieldOwnedFirewallRuleCount -ne 0) {
        throw 'QuietShield-owned firewall rules were unexpectedly detected.'
    }
    if ([string]$guiValidation.Status -cne 'Passed') {
        throw ('Phase 9 GUI validation failed: ' + (@($guiValidation.Errors) -join ' | '))
    }
    $phase8GuiValidation = $guiValidation.Phase8Baseline
    if ([string]$phase8GuiValidation.Status -cne 'Passed') {
        throw ('The preserved Phase 8 GUI baseline failed during Phase 9 validation: ' + (@($phase8GuiValidation.Errors) -join ' | '))
    }
    $phase7GuiValidation = $phase8GuiValidation.Phase7Baseline
    if ([string]$phase7GuiValidation.Status -cne 'Passed') {
        throw ('The preserved Phase 7 GUI baseline failed during Phase 9 validation: ' + (@($phase7GuiValidation.Errors) -join ' | '))
    }
    $phase6GuiValidation = $phase7GuiValidation.Phase6Baseline
    if ([string]$phase6GuiValidation.Status -cne 'Passed') {
        throw ('The preserved Phase 6 GUI baseline failed during Phase 9 validation: ' + (@($phase6GuiValidation.Errors) -join ' | '))
    }
    if ([int]$phase6GuiValidation.PageCount -ne 17) {
        throw ('Phase 9 GUI validation did not navigate every planned page. Count=' + [string]$phase6GuiValidation.PageCount)
    }
    if (@($phase6GuiValidation.Resolutions).Count -ne 3 -or @($phase6GuiValidation.Resolutions | Where-Object { -not [bool]$_.Passed }).Count -ne 0) {
        throw 'Phase 6 GUI validation did not pass every required window resolution.'
    }
    if (@($phase6GuiValidation.Scaling).Count -ne 4 -or @($phase6GuiValidation.Scaling | Where-Object { -not [bool]$_.Passed }).Count -ne 0) {
        throw 'Phase 6 GUI validation did not pass every required DPI scaling model.'
    }
    foreach ($requiredGuiFlag in @('MaximizedStatePassed', 'LongTextPassed', 'InventoryVirtualized', 'KeyboardNavigationPassed', 'UiResponsive')) {
        if (-not [bool]$phase6GuiValidation.$requiredGuiFlag) {
            throw ('Phase 6 GUI validation flag failed: ' + $requiredGuiFlag)
        }
    }
    foreach ($requiredPhase7Flag in @('ApplicationInventorySmokePassed', 'ProfileAndPolicySimulationPassed', 'PlannerSmokePassed', 'UpdatedTablesVirtualized', 'SimulationOnlyBannerPassed', 'MisleadingEnforcementControlsAbsent', 'UpdatedPagesResponsive')) {
        if (-not [bool]$phase7GuiValidation.$requiredPhase7Flag) {
            throw ('Phase 7 GUI validation flag failed: ' + $requiredPhase7Flag)
        }
    }

    foreach ($requiredPhase8Flag in @('TransactionPlanSmokePassed', 'PlanExportSmokePassed', 'BackupRollbackReadinessPassed', 'PlanViewerVirtualized', 'MisleadingEnforcementControlsAbsent', 'InactiveBannerPassed', 'LongTextAffordancesPassed', 'UpdatedPageResponsive')) {
        if (-not [bool]$phase8GuiValidation.$requiredPhase8Flag) {
            throw ('Phase 8 GUI validation flag failed: ' + $requiredPhase8Flag)
        }
    }
    foreach ($requiredPhase9Flag in @('RehearsalStatusSectionPassed', 'DedicatedTestBannerPassed', 'PermanentEnforcementInactive', 'MisleadingPermanentControlsAbsent', 'Responsive')) {
        if (-not [bool]$guiValidation.$requiredPhase9Flag) { throw ('Phase 9 GUI validation flag failed: ' + $requiredPhase9Flag) }
    }
    if (-not (Test-Path -LiteralPath $planExportPath -PathType Leaf)) { throw 'The WPF Phase 9 smoke did not export its requested read-only plan.' }
    $exportedPlan = Get-Content -LiteralPath $planExportPath -Raw | ConvertFrom-Json
    if ([bool]$exportedPlan.canExecute) { throw 'The exported Phase 8 plan unexpectedly permits execution.' }

    $programLockFixture = Join-Path $root 'tests\Fixtures\phase8-program-lock-backup.json'
    $programLockDryRunPath = Join-Path $testResults 'phase8-transaction-dry-run.json'
    Write-Output 'Running the read-only Program Lock transaction, rollback, interrupted recovery, and backup smoke.'
    $programLockLauncher = Join-Path $root 'Test-ProgramLockTransaction.bat'
    Invoke-QuietShieldCommand -FilePath $programLockLauncher -ArgumentList @('-BackupPath', $programLockFixture, '-OutputPath', $programLockDryRunPath)
    $programLockDryRun = Get-Content -LiteralPath $programLockDryRunPath -Raw | ConvertFrom-Json
    if ([string]$programLockDryRun.status -cne 'Passed' -or [bool]$programLockDryRun.canExecute -or
        -not [bool]$programLockDryRun.rollbackSimulationPassed -or -not [bool]$programLockDryRun.interruptedRecoverySimulationPassed) {
        throw 'The Phase 8 transaction or recovery dry-run failed its safety contract.'
    }

    Write-Output 'Showing the validated read-only Program Lock transaction state.'
    Invoke-QuietShieldCommand -FilePath (Join-Path $root 'Show-ProgramLockTransactionState.bat') -ArgumentList @('-BackupPath', $programLockFixture)

    Write-Output 'Running emergency Program Lock restore in WhatIf mode against a valid QuietShield fixture.'
    Invoke-QuietShieldCommand -FilePath (Join-Path $root 'Emergency-Restore-ProgramLock.bat') -ArgumentList @('-BackupPath', $programLockFixture, '-WhatIf')

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
    $firewallAttemptRecordsHashAfter = if (Test-Path -LiteralPath $firewallAttemptRecordsPath -PathType Leaf) { (Get-FileHash -LiteralPath $firewallAttemptRecordsPath -Algorithm SHA256).Hash } else { '[absent]' }
    if ($attemptRecordsHashBefore -cne $attemptRecordsHashAfter) { throw 'Dry validation changed the append-only rehearsal attempt records.' }
    if ($firewallAttemptRecordsHashBefore -cne $firewallAttemptRecordsHashAfter) { throw 'Dry validation changed the append-only Firewall rehearsal attempt records.' }
    if ($after.IsAdministrator) {
        throw 'Validation unexpectedly ran with Administrator elevation.'
    }
    if ($after.QuietShieldServiceCount -ne 0) {
        throw 'A QuietShield Windows service was registered during validation.'
    }

    $safetyComparison = Compare-QuietShieldSafetySnapshots -Before $before -After $after
    if (-not [bool]$safetyComparison.PersistentMatch) {
        throw ('Persistent safety snapshot changed during validation: ' + (@($safetyComparison.PersistentDifferences) -join ', '))
    }

    $validation = [ordered]@{
        schemaVersion = 9
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
        phase6GuiValidation = $phase6GuiValidation
        phase7ProgramConnectionLock = $phase7GuiValidation
        phase8ProgramLockTransaction = [ordered]@{
            gui = $phase8GuiValidation
            planExport = $planExportPath
            transactionDryRun = $programLockDryRunPath
            deterministicPlanGeneration = 'Passed'
            backupValidation = 'Passed'
            rollbackSimulation = 'Passed'
            interruptedRecoverySimulation = 'Passed'
            emergencyRestoreWhatIf = 'Passed'
            modifyingWindowsImplementationRegistered = $false
            realEnforcement = $false
        }
        phase9FirewallRehearsal = [ordered]@{
            gui = $guiValidation
            probeExecutable = $probePath
            dryTransactionState = $phase9DryStatePath
            endpoint = ([string]$phase9DryState.rule.remoteAddress + ':443')
            probePreBlockSuccess = 'Passed'
            watchdogSimulation = $phase9WatchdogSimulation
            restoreWhatIf = 'Passed'
            temporaryFirewallRuleCreated = $false
            realRehearsal = 'NotRunPendingExplicitApproval'
            attemptRecordsUnchanged = $true
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
            phase = 'Phase9ControlledProgramLockFirewallRehearsalDryValidation'
        }
        safety = [ordered]@{
            administrator = $after.IsAdministrator
            quietShieldServiceCount = $after.QuietShieldServiceCount
            firewallUnchanged = $true
            dnsUnchanged = $true
            adaptersUnchanged = $true
            adapterIdentityUnchanged = $true
            adapterConfigurationUnchanged = $true
            adapterOperationalEvents = @($safetyComparison.AdapterOperationalEvents)
            startupUnchanged = $true
            quietShieldWfpUnchanged = $true
            quietShieldRegistryUnchanged = $true
            registryMutationCommandsPresent = $false
            certificateCommandsPresent = $false
            securitySettingMutationCommandsPresent = $false
        }
        logPath = $logPath
    }

    $validation | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $resultPath -Encoding UTF8
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
