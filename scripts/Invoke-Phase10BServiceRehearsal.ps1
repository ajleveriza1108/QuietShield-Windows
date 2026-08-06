[CmdletBinding()]
param([switch]$ApprovedPhase10BServiceInstallationRehearsal)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ServiceActivation.Script.Common.ps1')
Assert-QuietShieldPowerShell51
if (-not $ApprovedPhase10BServiceInstallationRehearsal) { throw 'The real rehearsal requires -ApprovedPhase10BServiceInstallationRehearsal.' }
if (-not (Test-QuietShieldAdministrator)) { throw 'The real rehearsal requires an already elevated Administrator console and never self-elevates.' }
$root = Get-QuietShieldRepositoryRoot
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logPath = Start-QuietShieldLog -Name 'phase10b-service-rehearsal'
$evidenceDirectory = Join-Path $root ('logs\phase10b-rehearsal-' + $timestamp)
New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
$probePath = Join-Path $root 'artifacts\bin\QuietShield.ConnectionProbe\x64\Release\net10.0\QuietShield.ConnectionProbe.exe'
$probeHash = Get-QuietShieldFileSha256 -Path $probePath
$rehearsalId = [Guid]::NewGuid()
$preStatePath = Join-Path $evidenceDirectory 'protected-before.json'
$postStatePath = Join-Path $evidenceDirectory 'protected-after.json'
$ruleName = ''
$serviceInstalled = $false
$allowedCommitted = $false

try {
    $before = Get-QuietShieldSafetySnapshot
    $before | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $preStatePath -Encoding UTF8
    if ($before.QuietShieldServiceCount -ne 0 -or @(Get-QuietShieldExactService).Count -ne 0) { throw 'The exact QuietShield service already exists; the controlled rehearsal refuses to begin.' }
    $existingProgramLockRules = @(Get-NetFirewallRule -Name 'QuietShield.ProgramLock.*' -ErrorAction SilentlyContinue)
    if ($existingProgramLockRules.Count -ne 0) { throw 'One or more pre-existing QuietShield Program Lock rules require review before the controlled rehearsal.' }
    $resolvedAddresses = @([Net.Dns]::GetHostAddresses('example.com') | Sort-Object -Property AddressFamily,IPAddressToString -Unique)
    $selectedAddress = $null
    foreach ($candidate in $resolvedAddresses) {
        & $probePath $candidate.ToString() '443' '5000' | Out-Null
        if ($LASTEXITCODE -eq 0) { $selectedAddress = $candidate; break }
    }
    if ($null -eq $selectedAddress) { throw 'The dedicated probe had no reachable literal endpoint before service installation.' }

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Install-QuietShieldService.ps1') -ApprovedServiceInstallation -ApprovedRehearsalId $rehearsalId.ToString('D')
    if ($LASTEXITCODE -ne 0) { throw 'Exact service installation failed.' }
    $serviceInstalled = $true
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Start-QuietShieldService.ps1') -ApprovedServiceStart
    if ($LASTEXITCODE -ne 0) { throw 'Exact service start failed.' }
    $ipcBefore = Join-Path $evidenceDirectory 'ipc-before.json'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Test-QuietShieldService.ps1') -ApprovedServiceTest -OutputPath $ipcBefore
    if ($LASTEXITCODE -ne 0) { throw 'Installed service IPC validation failed.' }

    $requestPath = Join-Path $evidenceDirectory 'blocked-request.json'
    $responsePath = Join-Path $evidenceDirectory 'blocked-response.json'
    [pscustomobject][ordered]@{ approvedRehearsalId = $rehearsalId.ToString('D'); profileId = 'phase10b.rehearsal'; stableApplicationIdentity = 'quietshield.connection-probe'; executablePath = $probePath; executableSha256 = $probeHash; policy = 'Blocked' } | ConvertTo-Json | Set-Content -LiteralPath $requestPath -Encoding UTF8
    & 'D:\QuietShield\Service\QuietShield.Service.exe' --control-request $requestPath --control-output $responsePath --pipe-name 'QuietShield.Service.v1'
    if ($LASTEXITCODE -ne 0) { throw 'The service refused or failed the exact Blocked transaction.' }
    $blockedResponse = Get-Content -LiteralPath $responsePath -Raw | ConvertFrom-Json
    $ruleName = [string]$blockedResponse.Payload.exactRuleName
    if ($ruleName -notmatch '\AQuietShield\.ProgramLock\.[0-9a-f]{32}\z') { throw 'The service returned an invalid deterministic rule name.' }
    $exactRule = @(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)
    if ($exactRule.Count -ne 1) { throw 'The exact QuietShield block rule was not found exactly once.' }
    & $probePath $selectedAddress.ToString() '443' '5000' | Out-Null
    if ($LASTEXITCODE -ne 10) { throw ('The dedicated probe was not blocked; exit code ' + [string]$LASTEXITCODE) }

    $requestPath = Join-Path $evidenceDirectory 'allowed-request.json'
    $responsePath = Join-Path $evidenceDirectory 'allowed-response.json'
    [pscustomobject][ordered]@{ approvedRehearsalId = $rehearsalId.ToString('D'); profileId = 'phase10b.rehearsal'; stableApplicationIdentity = 'quietshield.connection-probe'; executablePath = $probePath; executableSha256 = $probeHash; policy = 'AllowedOnAll' } | ConvertTo-Json | Set-Content -LiteralPath $requestPath -Encoding UTF8
    & 'D:\QuietShield\Service\QuietShield.Service.exe' --control-request $requestPath --control-output $responsePath --pipe-name 'QuietShield.Service.v1'
    if ($LASTEXITCODE -ne 0) { throw 'The service refused or failed the exact AllowedOnAll transaction.' }
    if (@(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue).Count -ne 0) { throw 'The exact QuietShield block rule remains after AllowedOnAll.' }
    $allowedCommitted = $true
    & $probePath $selectedAddress.ToString() '443' '5000' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Dedicated probe connectivity did not return after AllowedOnAll.' }

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Stop-QuietShieldService.ps1') -ApprovedServiceStop
    if ($LASTEXITCODE -ne 0) { throw 'Exact service stop before restart failed.' }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Start-QuietShieldService.ps1') -ApprovedServiceStart
    if ($LASTEXITCODE -ne 0) { throw 'Exact service restart failed.' }
    $ipcRestart = Join-Path $evidenceDirectory 'ipc-after-restart.json'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Test-QuietShieldService.ps1') -ApprovedServiceTest -OutputPath $ipcRestart
    if ($LASTEXITCODE -ne 0) { throw 'Service IPC validation after restart failed.' }
    $restartStatus = Get-Content -LiteralPath $ipcRestart -Raw | ConvertFrom-Json
    if ([string]$restartStatus.serviceStatus.lastKnownGoodPolicyStatus -cnotmatch 'Validated') { throw 'Last-known-good policy status did not recover after restart.' }

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Stop-QuietShieldService.ps1') -ApprovedServiceStop
    if ($LASTEXITCODE -ne 0) { throw 'Final exact service stop failed.' }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Uninstall-QuietShieldService.ps1') -ApprovedServiceUninstall
    if ($LASTEXITCODE -ne 0) { throw 'Exact service uninstall failed.' }
    $serviceInstalled = $false
    if (@(Get-QuietShieldExactService).Count -ne 0) { throw 'The exact QuietShield service remains after uninstall.' }
    if (-not [string]::IsNullOrWhiteSpace($ruleName) -and @(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue).Count -ne 0) { throw 'The exact rehearsal rule remains after cleanup.' }
    & $probePath $selectedAddress.ToString() '443' '5000' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Probe connectivity was not restored after service cleanup.' }
    $after = Get-QuietShieldSafetySnapshot
    $after | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $postStatePath -Encoding UTF8
    $comparison = Compare-QuietShieldSafetySnapshots -Before $before -After $after
    if (-not [bool]$comparison.PersistentMatch) { throw ('Protected Windows state changed: ' + (@($comparison.PersistentDifferences) -join ', ')) }
    $report = @"
# Phase 10B Controlled Service Activation Report

Status: **Passed**

- Exact service install/start: Passed
- Local authorized named-pipe IPC: Passed
- Dedicated probe Blocked transaction: Passed
- Exact AllowedOnAll removal: Passed
- Probe connectivity restoration: Passed
- Service restart and last-known-good recovery: Passed
- Exact service stop/uninstall: Passed
- Remaining exact rehearsal rules: 0
- Protected persistent Windows state: Unchanged
- Restart required: No

Only QuietShield.ConnectionProbe was targeted. No DNS, WFP, adapter, unrelated Firewall rule, registry, startup, certificate, or security setting was changed. Transaction-specific identifiers and endpoint addresses remain only in local evidence.
"@
    Set-Content -LiteralPath (Join-Path $root 'PHASE-10B-SERVICE-ACTIVATION-REPORT.md') -Value $report -Encoding UTF8
    [pscustomobject]@{ status = 'Passed'; rehearsalId = $rehearsalId.ToString('D'); exactRuleName = $ruleName; serviceAbsent = $true; remainingExactRules = 0; connectivityRestored = $true; restartRequired = $false; protectedState = 'Unchanged'; evidenceDirectory = $evidenceDirectory; log = $logPath } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $evidenceDirectory 'result.json') -Encoding UTF8
}
catch {
    $primaryFailure = $_
    if ($serviceInstalled) {
        try {
            if (-not $allowedCommitted -and -not [string]::IsNullOrWhiteSpace($ruleName)) { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Restore-QuietShieldServiceState.ps1') -ApprovedEmergencyRestore -CleanupForUninstall -StateRoot 'D:\QuietShield\State' -Confirm:$false }
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Uninstall-QuietShieldService.ps1') -ApprovedServiceUninstall -Confirm:$false
        }
        catch { Write-Error ('Exact emergency cleanup also failed: ' + $_.Exception.Message) }
    }
    throw $primaryFailure
}
finally { Stop-QuietShieldLog }
