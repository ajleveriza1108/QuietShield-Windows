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
$logPath = Start-QuietShieldLog -Name 'phase10a-validation'
$resultPath = Join-Path $root ('logs\phase10a-validation-' + $timestamp + '.json')
$preStatePath = Join-Path $root ('logs\phase10a-protected-before-' + $timestamp + '.json')
$postStatePath = Join-Path $root ('logs\phase10a-protected-after-' + $timestamp + '.json')
$attemptRecordsPath = Join-Path $root 'artifacts\dns-rehearsal\attempt-records.jsonl'
$firewallAttemptRecordsPath = Join-Path $root 'artifacts\program-lock-rehearsal\attempts.jsonl'

function Get-OptionalFileHash {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path -PathType Leaf) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
    return '[absent]'
}

function New-ProcessStartInfo {
    param([string]$FilePath, [string]$Arguments)
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
    $before | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $preStatePath -Encoding UTF8
    if ($before.QuietShieldServiceCount -ne 0) { throw 'A QuietShield Windows service was registered before Phase 10A validation.' }
    $dnsEvidenceHashBefore = Get-OptionalFileHash -Path $attemptRecordsPath
    $firewallEvidenceHashBefore = Get-OptionalFileHash -Path $firewallAttemptRecordsPath

    Write-Output 'Parsing every PowerShell script with the Windows PowerShell 5.1 parser.'
    $parseFailures = @()
    foreach ($scriptFile in Get-ChildItem -LiteralPath (Join-Path $root 'scripts') -Filter '*.ps1' -File -Recurse) {
        $tokens = $null
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($scriptFile.FullName, [ref]$tokens, [ref]$errors)
        foreach ($parseError in @($errors)) {
            $parseFailures += ('{0}:{1}: {2}' -f $scriptFile.FullName, $parseError.Extent.StartLineNumber, $parseError.Message)
        }
    }
    if ($parseFailures.Count -ne 0) { throw ('PowerShell parser failures: ' + ($parseFailures -join ' | ')) }

    $solution = Join-Path $root 'QuietShield.sln'
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @('restore', $solution, '-p:Platform=x64')
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @('build', $solution, '-c', 'Debug', '--no-restore', '-p:Platform=x64')
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @('build', $solution, '-c', 'Release', '--no-restore', '-p:Platform=x64')
    $msbuild = Get-QuietShieldMSBuildPath
    Invoke-QuietShieldCommand -FilePath $msbuild -ArgumentList @($solution, '/m', '/nologo', '/v:minimal', '/p:Configuration=Release', '/p:Platform=x64', ('/p:RestorePackagesPath=' + $env:NUGET_PACKAGES))

    $testResults = Join-Path $root ('artifacts\test-results\phase10a-' + $timestamp)
    New-Item -ItemType Directory -Path $testResults -Force | Out-Null
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @('test', $solution, '-c', 'Release', '--no-build', '--no-restore', '-p:Platform=x64', '--results-directory', $testResults, '--logger', 'trx')
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @('test', (Join-Path $root 'tests\QuietShield.Windows.Tests\QuietShield.Windows.Tests.csproj'), '-c', 'Release', '--no-build', '--no-restore', '--filter', 'FullyQualifiedName~Phase10A')

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

    $communicationDirectory = Join-Path $root ('artifacts\phase10a\communication-' + $timestamp)
    Invoke-QuietShieldCommand -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $root 'scripts\Test-ServiceCommunication.ps1'), '-OutputDirectory', $communicationDirectory)
    $communication = Get-Content -LiteralPath (Join-Path $communicationDirectory 'ipc-result.json') -Raw | ConvertFrom-Json
    if ([string]$communication.status -cne 'Passed' -or [string]$communication.modifyingRequestStatus -cne 'NotActive') { throw 'The diagnostic IPC validation failed.' }

    $guiDirectory = Join-Path $root ('artifacts\phase10a\gui-' + $timestamp)
    New-Item -ItemType Directory -Path $guiDirectory -Force | Out-Null
    $pipeName = 'QuietShield.Service.GuiValidation.' + [Guid]::NewGuid().ToString('N')
    $servicePath = Join-Path $root 'artifacts\bin\QuietShield.Service\Release\net10.0-windows\QuietShield.Service.exe'
    $appPath = Join-Path $root 'artifacts\bin\QuietShield.App\Release\net10.0-windows\QuietShield.App.exe'
    $guiResultPath = Join-Path $guiDirectory 'gui-validation.json'
    $planPath = Join-Path $guiDirectory 'program-lock-plan.json'
    $stateRoot = Join-Path $guiDirectory 'state'
    $serviceArguments = '--diagnostic --pipe-name "{0}" --state-root "{1}" --duration-seconds 20' -f $pipeName, $stateRoot
    $serviceProcess = New-Object System.Diagnostics.Process
    $serviceProcess.StartInfo = New-ProcessStartInfo -FilePath $servicePath -Arguments $serviceArguments
    if (-not $serviceProcess.Start()) { throw 'The Phase 10A diagnostic GUI host could not start.' }
    Start-Sleep -Milliseconds 1200
    if ($serviceProcess.HasExited) { throw ('The Phase 10A diagnostic GUI host exited early with code ' + $serviceProcess.ExitCode) }
    $appArguments = '--phase10a-smoke --service-pipe-name "{0}" --gui-validation-output "{1}" --plan-export-output "{2}"' -f $pipeName, $guiResultPath, $planPath
    $appProcess = New-Object System.Diagnostics.Process
    $appProcess.StartInfo = New-ProcessStartInfo -FilePath $appPath -Arguments $appArguments
    if (-not $appProcess.Start()) { throw 'The WPF Phase 10A smoke process could not start.' }
    if (-not $appProcess.WaitForExit(30000)) { throw ('The WPF smoke process did not exit within 30 seconds. Process ID: ' + $appProcess.Id) }
    $appProcess.WaitForExit()
    $appProcess.Refresh()
    if (-not $appProcess.HasExited -or $appProcess.ExitCode -ne 0) { throw ('The WPF smoke process failed with exit code ' + $appProcess.ExitCode) }
    if (-not $serviceProcess.WaitForExit(35000)) { throw ('The diagnostic GUI host did not stop within its bounded duration. Process ID: ' + $serviceProcess.Id) }
    $serviceProcess.WaitForExit()
    $serviceProcess.Refresh()
    if (-not $serviceProcess.HasExited -or $serviceProcess.ExitCode -ne 0) { throw ('The diagnostic GUI host failed with exit code ' + $serviceProcess.ExitCode) }
    $guiValidation = Get-Content -LiteralPath $guiResultPath -Raw | ConvertFrom-Json
    if ([string]$guiValidation.Status -cne 'Passed') { throw 'The responsive Phase 10A GUI validation did not pass.' }
    $appProcess.Dispose()
    $serviceProcess.Dispose()

    $after = Get-QuietShieldSafetySnapshot
    $after | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $postStatePath -Encoding UTF8
    if ($after.IsAdministrator) { throw 'Phase 10A validation unexpectedly ran elevated.' }
    if ($after.QuietShieldServiceCount -ne 0) { throw 'A QuietShield Windows service was registered during Phase 10A validation.' }
    if ((Get-OptionalFileHash -Path $attemptRecordsPath) -cne $dnsEvidenceHashBefore) { throw 'Phase 5 DNS evidence changed during Phase 10A validation.' }
    if ((Get-OptionalFileHash -Path $firewallAttemptRecordsPath) -cne $firewallEvidenceHashBefore) { throw 'Phase 9 Firewall evidence changed during Phase 10A validation.' }
    $comparison = Compare-QuietShieldSafetySnapshots -Before $before -After $after
    if (-not [bool]$comparison.PersistentMatch) { throw ('Protected Windows state changed: ' + (@($comparison.PersistentDifferences) -join ', ')) }

    $result = [ordered]@{
        schemaVersion = 10
        phase = 'Phase10APersistentServiceFoundation'
        timestamp = (Get-Date).ToString('o')
        status = 'Passed'
        powershell51Parsing = 'Passed'
        dotnetRestore = 'Passed'
        debugX64Build = 'Passed'
        releaseX64Build = 'Passed'
        visualStudio2026Msbuild = 'Passed'
        tests = [ordered]@{ total = $testTotal; passed = $testPassed; failed = $testFailed }
        serviceDiagnostic = [ordered]@{ status = 'Passed'; gracefulShutdown = $true; registeredServiceCount = [int]$after.QuietShieldServiceCount }
        ipc = [ordered]@{ status = 'Passed'; ping = [string]$communication.ping; modifyingRequest = [string]$communication.modifyingRequestStatus; transport = 'LocalCurrentUserOnlyNamedPipe' }
        persistentState = [ordered]@{ malformedRefusal = 'Passed'; atomicReplacement = 'Passed'; lastKnownGoodRecovery = 'Passed'; schemaMigrationRefusal = 'Passed' }
        gui = $guiValidation
        protectedWindowsState = [ordered]@{
            status = 'Unchanged'
            firewall = 'Unchanged'
            dns = 'Unchanged'
            wfp = 'Unchanged'
            adapters = 'Unchanged'
            registry = 'Unchanged'
            startup = 'Unchanged'
            services = 'Unchanged'
            administrator = $false
            operationalAdapterEvents = @($comparison.AdapterOperationalEvents)
        }
        preState = $preStatePath
        postState = $postStatePath
        log = $logPath
    }
    $result | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $resultPath -Encoding UTF8
    Write-Output ('Phase 10A validation passed: {0}/{1} tests. Result: {2}' -f $testPassed, $testTotal, $resultPath)
}
finally {
    Stop-QuietShieldLog
}
