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
$logPath = Start-QuietShieldLog -Name 'phase10b-dry-validation'
$resultPath = Join-Path $root ('logs\phase10b-dry-validation-' + $timestamp + '.json')
$preStatePath = Join-Path $root ('logs\phase10b-protected-before-' + $timestamp + '.json')
$postStatePath = Join-Path $root ('logs\phase10b-protected-after-' + $timestamp + '.json')
$dnsEvidencePath = Join-Path $root 'artifacts\dns-rehearsal\attempt-records.jsonl'
$firewallEvidencePath = Join-Path $root 'artifacts\program-lock-rehearsal\attempts.jsonl'

function Get-OptionalFileHash {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '[absent]' }
    return Get-QuietShieldFileSha256 -Path $Path
}

function New-Phase10BProcessStartInfo {
    param([Parameter(Mandatory = $true)][string]$FilePath, [Parameter(Mandatory = $true)][string]$Arguments)
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = $Arguments
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    return $startInfo
}

try {
    Assert-QuietShieldToolchain
    $before = Get-QuietShieldSafetySnapshot
    $before | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $preStatePath -Encoding UTF8
    if ($before.IsAdministrator) { throw 'The Phase 10B dry gate must not run elevated.' }
    if ($before.QuietShieldServiceCount -ne 0 -or @(Get-QuietShieldExactService).Count -ne 0) { throw 'A QuietShield service is registered; the non-installing Phase 10B dry gate refused to continue.' }
    $beforeRules = @(Get-NetFirewallRule -Name 'QuietShield.ProgramLock.*' -ErrorAction SilentlyContinue)
    if ($beforeRules.Count -ne 0) { throw 'A QuietShield Program Lock rule exists; the non-installing Phase 10B dry gate refused to continue.' }
    $dnsEvidenceHashBefore = Get-OptionalFileHash -Path $dnsEvidencePath
    $firewallEvidenceHashBefore = Get-OptionalFileHash -Path $firewallEvidencePath

    Write-Output 'Parsing every PowerShell script with the Windows PowerShell 5.1 parser.'
    $parseFailures = @()
    foreach ($scriptFile in Get-ChildItem -LiteralPath (Join-Path $root 'scripts') -Filter '*.ps1' -File -Recurse) {
        $tokens = $null
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($scriptFile.FullName, [ref]$tokens, [ref]$errors)
        foreach ($parseError in @($errors)) { $parseFailures += ('{0}:{1}: {2}' -f $scriptFile.FullName, $parseError.Extent.StartLineNumber, $parseError.Message) }
    }
    if ($parseFailures.Count -ne 0) { throw ('PowerShell parser failures: ' + ($parseFailures -join ' | ')) }

    $solution = Join-Path $root 'QuietShield.sln'
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @('restore', $solution, '-p:Platform=x64')
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @('build', $solution, '-c', 'Debug', '--no-restore', '-p:Platform=x64')
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @('build', $solution, '-c', 'Release', '--no-restore', '-p:Platform=x64')
    $msbuild = Get-QuietShieldMSBuildPath
    Invoke-QuietShieldCommand -FilePath $msbuild -ArgumentList @($solution, '/m', '/nologo', '/v:minimal', '/p:Configuration=Release', '/p:Platform=x64', ('/p:RestorePackagesPath=' + $env:NUGET_PACKAGES))

    $testResults = Join-Path $root ('artifacts\test-results\phase10b-' + $timestamp)
    New-Item -ItemType Directory -Path $testResults -Force | Out-Null
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @('test', $solution, '-c', 'Release', '--no-build', '--no-restore', '-p:Platform=x64', '--results-directory', $testResults, '--logger', 'trx')
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @('test', (Join-Path $root 'tests\QuietShield.Windows.Tests\QuietShield.Windows.Tests.csproj'), '-c', 'Release', '--no-build', '--no-restore', '--filter', 'FullyQualifiedName~Phase10B')

    $testTotal = 0
    $testPassed = 0
    $testFailed = 0
    foreach ($trx in Get-ChildItem -LiteralPath $testResults -Filter '*.trx' -File -Recurse) {
        [xml]$document = Get-Content -LiteralPath $trx.FullName -Raw
        $counters = $document.SelectSingleNode("//*[local-name()='Counters']")
        if ($null -eq $counters) { throw ('TRX counters were missing: ' + $trx.FullName) }
        $testTotal += [int]$counters.total
        $testPassed += [int]$counters.passed
        $testFailed += [int]$counters.failed
    }
    if ($testTotal -le 0 -or $testPassed -ne $testTotal -or $testFailed -ne 0) { throw 'The complete automated-test TRX totals were not all passed.' }

    $packageOutput = & (Join-Path $PSScriptRoot 'New-QuietShieldServicePackage.ps1')
    $package = Test-QuietShieldServicePackage -PackageRoot (Join-Path $root 'artifacts\service-package\Release')
    if ([string]::IsNullOrWhiteSpace([string]$package.PayloadSha256)) { throw 'The exact service package did not validate.' }
    $dryRehearsalId = [Guid]'10b00000-0000-4000-8000-000000000001'
    $installPlan = & (Join-Path $PSScriptRoot 'Install-QuietShieldService.ps1') -ApprovedRehearsalId $dryRehearsalId -WhatIf
    if (($installPlan -join "`n") -cnotmatch 'InstallationPlanValidated' -or ($installPlan -join "`n") -cnotmatch 'modifyingCommandInvoked') { throw 'The exact service installation dry run did not validate.' }
    $restorePlan = & (Join-Path $PSScriptRoot 'Restore-QuietShieldServiceState.ps1') -WhatIf
    if (($restorePlan -join "`n") -cnotmatch 'WhatIfPassed' -or ($restorePlan -join "`n") -cnotmatch 'modifyingCommandInvoked') { throw 'The exact service restore WhatIf plan did not validate.' }
    $lifecycleSimulation = & (Join-Path $PSScriptRoot 'Test-QuietShieldServiceLifecycleSimulations.ps1')
    if (($lifecycleSimulation -join "`n") -cnotmatch 'Passed') { throw 'The service lifecycle simulations did not pass.' }

    $communicationDirectory = Join-Path $root ('artifacts\phase10b\communication-' + $timestamp)
    Invoke-QuietShieldCommand -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $root 'scripts\Test-ServiceCommunication.ps1'), '-OutputDirectory', $communicationDirectory)
    $communication = Get-Content -LiteralPath (Join-Path $communicationDirectory 'ipc-result.json') -Raw | ConvertFrom-Json
    if ([string]$communication.status -cne 'Passed' -or [string]$communication.modifyingRequestStatus -cne 'NotActive') { throw 'The non-installed diagnostic IPC validation failed.' }

    $guiDirectory = Join-Path $root ('artifacts\phase10b\gui-' + $timestamp)
    New-Item -ItemType Directory -Path $guiDirectory -Force | Out-Null
    $pipeName = 'QuietShield.Service.Phase10B.Gui.' + [Guid]::NewGuid().ToString('N')
    $servicePath = Join-Path $root 'artifacts\bin\QuietShield.Service\Release\net10.0-windows\QuietShield.Service.exe'
    $appPath = Join-Path $root 'artifacts\bin\QuietShield.App\Release\net10.0-windows\QuietShield.App.exe'
    $guiResultPath = Join-Path $guiDirectory 'gui-validation.json'
    $planPath = Join-Path $guiDirectory 'program-lock-plan.json'
    $stateRoot = Join-Path $guiDirectory 'diagnostic-state'
    $serviceArguments = '--diagnostic --pipe-name "{0}" --state-root "{1}" --duration-seconds 20' -f $pipeName, $stateRoot
    $serviceProcess = New-Object System.Diagnostics.Process
    $serviceProcess.StartInfo = New-Phase10BProcessStartInfo -FilePath $servicePath -Arguments $serviceArguments
    if (-not $serviceProcess.Start()) { throw 'The non-installed Phase 10B diagnostic host could not start.' }
    Start-Sleep -Milliseconds 1200
    if ($serviceProcess.HasExited) { throw ('The Phase 10B diagnostic host exited early with code ' + $serviceProcess.ExitCode) }
    $appArguments = '--phase10b-smoke --service-pipe-name "{0}" --gui-validation-output "{1}" --plan-export-output "{2}"' -f $pipeName, $guiResultPath, $planPath
    $appProcess = New-Object System.Diagnostics.Process
    $appProcess.StartInfo = New-Phase10BProcessStartInfo -FilePath $appPath -Arguments $appArguments
    if (-not $appProcess.Start()) { throw 'The WPF Phase 10B GUI smoke process could not start.' }
    if (-not $appProcess.WaitForExit(30000)) { throw ('The WPF Phase 10B GUI process timed out. Process ID: ' + $appProcess.Id) }
    $appProcess.WaitForExit()
    $appProcess.Refresh()
    if (-not $appProcess.HasExited -or $appProcess.ExitCode -ne 0) { throw ('The WPF Phase 10B GUI process failed with exit code ' + $appProcess.ExitCode) }
    if (-not $serviceProcess.WaitForExit(35000)) { throw ('The diagnostic host timed out. Process ID: ' + $serviceProcess.Id) }
    $serviceProcess.WaitForExit()
    $serviceProcess.Refresh()
    if (-not $serviceProcess.HasExited -or $serviceProcess.ExitCode -ne 0) { throw ('The diagnostic host failed with exit code ' + $serviceProcess.ExitCode) }
    $guiValidation = Get-Content -LiteralPath $guiResultPath -Raw | ConvertFrom-Json
    if ([string]$guiValidation.Status -cne 'Passed') { throw 'The responsive Phase 10B GUI validation did not pass.' }
    $appProcess.Dispose()
    $serviceProcess.Dispose()

    $after = Get-QuietShieldSafetySnapshot
    $after | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $postStatePath -Encoding UTF8
    if ($after.IsAdministrator) { throw 'The Phase 10B dry gate unexpectedly became elevated.' }
    if ($after.QuietShieldServiceCount -ne 0 -or @(Get-QuietShieldExactService).Count -ne 0) { throw 'A QuietShield service was registered during the non-installing dry gate.' }
    if (@(Get-NetFirewallRule -Name 'QuietShield.ProgramLock.*' -ErrorAction SilentlyContinue).Count -ne 0) { throw 'A QuietShield Program Lock rule was created during the non-installing dry gate.' }
    if ((Get-OptionalFileHash -Path $dnsEvidencePath) -cne $dnsEvidenceHashBefore) { throw 'Phase 5 DNS blocker evidence changed during Phase 10B validation.' }
    if ((Get-OptionalFileHash -Path $firewallEvidencePath) -cne $firewallEvidenceHashBefore) { throw 'Phase 9 Firewall evidence changed during Phase 10B validation.' }
    $comparison = Compare-QuietShieldSafetySnapshots -Before $before -After $after
    if (-not [bool]$comparison.PersistentMatch) { throw ('Protected Windows state changed: ' + (@($comparison.PersistentDifferences) -join ', ')) }

    $result = [ordered]@{
        schemaVersion = 10
        phase = 'Phase10BControlledServiceActivationDryGate'
        timestamp = [DateTimeOffset]::Now.ToString('O')
        status = 'Passed'
        powershell51Parsing = 'Passed'
        debugX64Build = 'Passed'
        releaseX64Build = 'Passed'
        visualStudio2026Msbuild = 'Passed'
        tests = [ordered]@{ total = $testTotal; passed = $testPassed; failed = $testFailed }
        servicePackage = [ordered]@{ status = 'Validated'; payloadSha256 = $package.PayloadSha256; sourceOutput = @($packageOutput) }
        serviceInstallation = [ordered]@{ status = 'DryRunPassed'; installed = $false; exactIdentity = 'QuietShieldService'; startup = 'AutomaticDelayedStart'; modifyingCommandInvoked = $false }
        emergencyRestore = [ordered]@{ status = 'WhatIfPassed'; modifyingCommandInvoked = $false }
        firewallTransactions = [ordered]@{ status = 'SimulationPassed'; supportedPolicies = @('Blocked','AllowedOnAll'); modifyingCommandInvoked = $false }
        ipc = [ordered]@{ status = 'Passed'; transport = 'LocalCurrentUserOnlyDiagnosticNamedPipe'; persistentServiceInstalled = $false }
        gui = $guiValidation
        protectedWindowsState = [ordered]@{ status = 'Unchanged'; serviceCount = [int]$after.QuietShieldServiceCount; remainingQuietShieldProgramLockRules = 0; persistentDifferences = @($comparison.PersistentDifferences); operationalAdapterEvents = @($comparison.AdapterOperationalEvents) }
        preState = $preStatePath
        postState = $postStatePath
        log = $logPath
    }
    $result | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $resultPath -Encoding UTF8
    Write-Output ('Phase 10B dry validation passed: {0}/{1} tests. No service was installed. Result: {2}' -f $testPassed, $testTotal, $resultPath)
}
finally {
    Stop-QuietShieldLog
}
