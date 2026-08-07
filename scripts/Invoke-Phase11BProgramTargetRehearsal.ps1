[CmdletBinding()]
param([switch]$ApprovedPhase11BProgramTargetRehearsal)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ServiceActivation.Script.Common.ps1')

Assert-QuietShieldPowerShell51

if (-not $ApprovedPhase11BProgramTargetRehearsal) {
    throw 'The real Phase 11B rehearsal requires -ApprovedPhase11BProgramTargetRehearsal.'
}

if (-not (Test-QuietShieldAdministrator)) {
    throw 'The real Phase 11B rehearsal requires an already elevated Administrator console and never self-elevates.'
}

$root = Get-QuietShieldRepositoryRoot
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logPath = Start-QuietShieldLog -Name 'phase11b-program-target-rehearsal'
$evidenceDirectory = Join-Path $root ('logs\phase11b-program-target-' + $timestamp)
New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null

$targetDirectory = Join-Path $root 'artifacts\phase11b\controlled-target'
$sourceProbe = Join-Path $root 'artifacts\bin\QuietShield.ConnectionProbe\x64\Release\net10.0\QuietShield.ConnectionProbe.exe'
$targetPath = Join-Path $targetDirectory 'QuietShield.CustomerProgramTarget.exe'
$rehearsalId = [Guid]::NewGuid()
$preStatePath = Join-Path $evidenceDirectory 'protected-before.json'
$postStatePath = Join-Path $evidenceDirectory 'protected-after.json'
$reportPath = Join-Path $root 'PHASE-11B-PROGRAM-TARGET-REPORT.md'

$ruleName = ''
$serviceInstalled = $false
$allowedCommitted = $false
$targetPrepared = $false

try {
    $before = Get-QuietShieldSafetySnapshot
    $before | ConvertTo-Json -Depth 10 |
        Set-Content -LiteralPath $preStatePath -Encoding UTF8

    if ([int]$before.QuietShieldServiceCount -ne 0 -or
        @(Get-QuietShieldExactService).Count -ne 0) {
        throw 'The exact QuietShield service already exists; Phase 11B refuses to begin.'
    }

    if (@(Get-NetFirewallRule -Name 'QuietShield.ProgramLock.*' -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'Pre-existing QuietShield Program Lock rules require review before Phase 11B.'
    }

    if (Test-Path -LiteralPath 'D:\QuietShield\Service') {
        throw 'D:\QuietShield\Service already exists before Phase 11B.'
    }

    if (-not (Test-Path -LiteralPath $sourceProbe -PathType Leaf)) {
        throw 'The validated Release connection test executable is missing.'
    }

    if (Test-Path -LiteralPath $targetDirectory) {
        Remove-Item -LiteralPath $targetDirectory -Recurse -Force
    }

    New-Item -ItemType Directory -Path $targetDirectory -Force | Out-Null
    Copy-Item -LiteralPath $sourceProbe -Destination $targetPath -Force
    $targetPrepared = $true

    $targetHash = Get-QuietShieldFileSha256 -Path $targetPath
    $targetIdentity = Get-QuietShieldApprovedProgramIdentity -Path $targetPath

    if ($targetIdentity -notmatch '\Awindows-exe:[0-9a-f]{32}\z') {
        throw 'The controlled target identity is invalid.'
    }

    if ($targetIdentity -ceq 'quietshield.connection-probe') {
        throw 'The controlled target identity still resolves to the legacy probe identity.'
    }

    $resolvedAddresses = @(
        [Net.Dns]::GetHostAddresses('example.com') |
            Sort-Object -Property AddressFamily, IPAddressToString -Unique
    )

    $selectedAddress = $null

    foreach ($candidate in $resolvedAddresses) {
        & $targetPath $candidate.ToString() '443' '5000' | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $selectedAddress = $candidate
            break
        }
    }

    if ($null -eq $selectedAddress) {
        throw 'The renamed controlled target had no reachable literal endpoint before service installation.'
    }

    & (Join-Path $PSScriptRoot 'Install-QuietShieldService.ps1') `
        -ApprovedServiceInstallation `
        -ApprovedRehearsalId $rehearsalId `
        -AuthorizedProgramPath $targetPath `
        -Confirm:$false | Write-Output

    $serviceInstalled = $true

    & (Join-Path $PSScriptRoot 'Start-QuietShieldService.ps1') `
        -ApprovedServiceStart `
        -Confirm:$false | Write-Output

    $ipcBefore = Join-Path $evidenceDirectory 'ipc-before.json'

    & (Join-Path $PSScriptRoot 'Test-QuietShieldService.ps1') `
        -ApprovedServiceTest `
        -OutputPath $ipcBefore | Write-Output

    $requestPath = Join-Path $evidenceDirectory 'blocked-request.json'
    $responsePath = Join-Path $evidenceDirectory 'blocked-response.json'

    [pscustomobject][ordered]@{
        approvedRehearsalId = $rehearsalId.ToString('D')
        profileId = 'phase11b.controlled-target'
        stableApplicationIdentity = $targetIdentity
        executablePath = $targetPath
        executableSha256 = $targetHash
        policy = 'Blocked'
    } | ConvertTo-Json |
        Set-Content -LiteralPath $requestPath -Encoding UTF8

    & 'D:\QuietShield\Service\QuietShield.Service.exe' `
        --control-request $requestPath `
        --control-output $responsePath `
        --pipe-name 'QuietShield.Service.v1'

    if ($LASTEXITCODE -ne 0) {
        throw 'The service refused or failed the generalized exact Blocked transaction.'
    }

    $blockedResponse = Get-Content -LiteralPath $responsePath -Raw | ConvertFrom-Json
    $ruleName = [string]$blockedResponse.Payload.exactRuleName

    if ($ruleName -notmatch '\AQuietShield\.ProgramLock\.[0-9a-f]{32}\z') {
        throw 'The service returned an invalid deterministic Program Lock rule name.'
    }

    $exactRule = @(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)
    if ($exactRule.Count -ne 1) {
        throw 'The generalized exact QuietShield block rule was not found exactly once.'
    }

    $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $exactRule[0]
    if ([IO.Path]::GetFullPath([string]$appFilter.Program) -cne [IO.Path]::GetFullPath($targetPath)) {
        throw 'The generalized block rule targeted a different executable.'
    }

    & $targetPath $selectedAddress.ToString() '443' '5000' | Out-Null
    if ($LASTEXITCODE -ne 10) {
        throw ('The renamed controlled target was not blocked; exit code ' + [string]$LASTEXITCODE)
    }

    $requestPath = Join-Path $evidenceDirectory 'allowed-request.json'
    $responsePath = Join-Path $evidenceDirectory 'allowed-response.json'

    [pscustomobject][ordered]@{
        approvedRehearsalId = $rehearsalId.ToString('D')
        profileId = 'phase11b.controlled-target'
        stableApplicationIdentity = $targetIdentity
        executablePath = $targetPath
        executableSha256 = $targetHash
        policy = 'AllowedOnAll'
    } | ConvertTo-Json |
        Set-Content -LiteralPath $requestPath -Encoding UTF8

    & 'D:\QuietShield\Service\QuietShield.Service.exe' `
        --control-request $requestPath `
        --control-output $responsePath `
        --pipe-name 'QuietShield.Service.v1'

    if ($LASTEXITCODE -ne 0) {
        throw 'The service refused or failed the generalized AllowedOnAll transaction.'
    }

    if (@(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'The exact QuietShield block rule remains after generalized AllowedOnAll.'
    }

    $allowedCommitted = $true

    & $targetPath $selectedAddress.ToString() '443' '5000' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Controlled-target connectivity did not return after AllowedOnAll.'
    }

    & (Join-Path $PSScriptRoot 'Stop-QuietShieldService.ps1') `
        -ApprovedServiceStop `
        -Confirm:$false | Write-Output

    & (Join-Path $PSScriptRoot 'Start-QuietShieldService.ps1') `
        -ApprovedServiceStart `
        -Confirm:$false | Write-Output

    $ipcRestart = Join-Path $evidenceDirectory 'ipc-after-restart.json'

    & (Join-Path $PSScriptRoot 'Test-QuietShieldService.ps1') `
        -ApprovedServiceTest `
        -OutputPath $ipcRestart | Write-Output

    $restartStatus = Get-Content -LiteralPath $ipcRestart -Raw | ConvertFrom-Json

    if ([string]$restartStatus.serviceStatus.lastKnownGoodPolicyStatus -cnotmatch 'Validated') {
        throw 'Last-known-good policy status did not recover after Phase 11B service restart.'
    }

    & (Join-Path $PSScriptRoot 'Stop-QuietShieldService.ps1') `
        -ApprovedServiceStop `
        -Confirm:$false | Write-Output

    & (Join-Path $PSScriptRoot 'Uninstall-QuietShieldService.ps1') `
        -ApprovedServiceUninstall `
        -Confirm:$false | Write-Output

    $serviceInstalled = $false

    if (@(Get-QuietShieldExactService).Count -ne 0) {
        throw 'The exact QuietShield service remains after Phase 11B uninstall.'
    }

    if (@(Get-NetFirewallRule -Name 'QuietShield.ProgramLock.*' -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'A QuietShield Program Lock rule remains after Phase 11B cleanup.'
    }

    & $targetPath $selectedAddress.ToString() '443' '5000' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Controlled-target connectivity was not restored after service cleanup.'
    }

    if (Test-Path -LiteralPath $targetDirectory) {
        Remove-Item -LiteralPath $targetDirectory -Recurse -Force
    }

    $targetPrepared = $false

    $after = Get-QuietShieldSafetySnapshot
    $after | ConvertTo-Json -Depth 10 |
        Set-Content -LiteralPath $postStatePath -Encoding UTF8

    $comparison = Compare-QuietShieldSafetySnapshots -Before $before -After $after

    if (-not [bool]$comparison.PersistentMatch) {
        throw ('Protected Windows state changed during Phase 11B: ' +
            (@($comparison.PersistentDifferences) -join ', '))
    }

    $report = @"
# Phase 11B Controlled Program Target Rehearsal

Status: **Passed**

- Authorized target identity: Path-derived
- Authorized target type: Renamed controlled non-system test executable
- Exact service install/start: Passed
- Local authorized named-pipe IPC: Passed
- Generalized Blocked transaction: Passed
- Exact AllowedOnAll removal: Passed
- Controlled-target connectivity restoration: Passed
- Service restart and last-known-good recovery: Passed
- Exact service stop/uninstall: Passed
- Remaining exact Program Lock rules: 0
- Protected persistent Windows state: Unchanged
- Restart required: No

The rehearsal proved that persistent Program Connection Lock authorization is no longer hard-coded to the literal `quietshield.connection-probe` stable identity. The authorized executable remained bound to one exact path, one exact SHA-256, one path-derived stable identity, and one approved rehearsal ID.

No installed customer application was targeted. No DNS, WFP, adapter, unrelated Firewall rule, startup, certificate, or unrelated security setting was changed.
"@

    Set-Content -LiteralPath $reportPath -Value $report -Encoding UTF8

    [pscustomobject][ordered]@{
        status = 'Passed'
        targetIdentityMode = 'PathDerived'
        targetType = 'RenamedControlledNonSystemExecutable'
        exactRuleName = $ruleName
        generalizedBlocked = 'Passed'
        allowedOnAllRemoval = 'Passed'
        connectivityRestored = $true
        serviceAbsent = $true
        remainingProgramLockRules = 0
        protectedState = 'Unchanged'
        restartRequired = $false
        evidenceDirectory = $evidenceDirectory
        log = $logPath
    } | ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath (Join-Path $evidenceDirectory 'result.json') -Encoding UTF8
}
catch {
    $primaryFailure = $_

    if ($serviceInstalled) {
        try {
            if (-not $allowedCommitted -and -not [string]::IsNullOrWhiteSpace($ruleName)) {
                & (Join-Path $PSScriptRoot 'Restore-QuietShieldServiceState.ps1') `
                    -ApprovedEmergencyRestore `
                    -CleanupForUninstall `
                    -StateRoot 'D:\QuietShield\State' `
                    -Confirm:$false | Write-Output
            }

            & (Join-Path $PSScriptRoot 'Uninstall-QuietShieldService.ps1') `
                -ApprovedServiceUninstall `
                -Confirm:$false | Write-Output
        }
        catch {
            Write-Error ('Exact Phase 11B emergency cleanup also failed: ' + $_.Exception.Message)
        }
    }

    throw $primaryFailure
}
finally {
    if ($targetPrepared -and (Test-Path -LiteralPath $targetDirectory)) {
        Remove-Item -LiteralPath $targetDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }

    Stop-QuietShieldLog
}
