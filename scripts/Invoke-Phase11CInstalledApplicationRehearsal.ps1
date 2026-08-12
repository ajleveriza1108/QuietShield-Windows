[CmdletBinding()]
param(
    [switch]$ApprovedPhase11CInstalledApplicationRehearsal,
    [string]$SelectionPath = 'D:\QuietShield-Phase11-Work\PHASE11C-SELECTION.json'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ServiceActivation.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'Phase11C.InstalledApp.Common.ps1')

Assert-QuietShieldPowerShell51

if (-not $ApprovedPhase11CInstalledApplicationRehearsal) {
    throw 'The real Phase 11C rehearsal requires -ApprovedPhase11CInstalledApplicationRehearsal.'
}

if (-not (Test-QuietShieldAdministrator)) {
    throw 'The real Phase 11C rehearsal requires an already elevated Administrator console and never self-elevates.'
}

if (-not (Test-Path -LiteralPath $SelectionPath -PathType Leaf)) {
    throw 'The explicit Phase 11C application selection marker is missing.'
}

$root = Get-QuietShieldRepositoryRoot
$selection = Get-Content -LiteralPath $SelectionPath -Raw | ConvertFrom-Json

if ([int]$selection.schemaVersion -ne 1 -or
    [string]$selection.phase -cne '11C' -or
    [string]$selection.status -cne 'ApprovedLocalSelection') {
    throw 'The Phase 11C selection marker identity is invalid.'
}

$currentCommit = (& git.exe -C $root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $currentCommit -cne [string]$selection.sourceCommit) {
    throw 'The Phase 11C selection marker does not match the current validated source commit.'
}

$targetPath = Assert-Phase11CSafeInstalledApplicationTarget `
    -Path ([string]$selection.executablePath) `
    -ProbeAdapter ([string]$selection.probeAdapter)

$targetHash = Get-QuietShieldFileSha256 -Path $targetPath
$targetIdentity = Get-QuietShieldApprovedProgramIdentity -Path $targetPath

if ($targetHash -cne ([string]$selection.sha256).ToUpperInvariant()) {
    throw 'The selected installed application changed after Phase 11C approval.'
}

if ($targetIdentity -cne [string]$selection.stableIdentity) {
    throw 'The selected installed application path-derived identity changed after Phase 11C approval.'
}

$runningBefore = @(Get-Phase11CRunningTargetProcesses -ExecutablePath $targetPath)
if ($runningBefore.Count -ne 0) {
    throw ('Close the selected installed application before Phase 11C. Running process IDs: ' +
        (@($runningBefore | ForEach-Object { [string]$_.processId }) -join ', '))
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logPath = Start-QuietShieldLog -Name 'phase11c-installed-app-rehearsal'
$evidenceDirectory = Join-Path $root ('logs\phase11c-installed-app-' + $timestamp)
$probeDirectory = Join-Path $evidenceDirectory 'probe'
New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $probeDirectory -Force | Out-Null

$preStatePath = Join-Path $evidenceDirectory 'protected-before.json'
$postStatePath = Join-Path $evidenceDirectory 'protected-after.json'
$reportPath = Join-Path $root 'PHASE-11C-INSTALLED-APP-REPORT.md'
$rehearsalId = [Guid]::NewGuid()
$ruleName = ''
$serviceInstalled = $false
$allowedCommitted = $false
$selectedAddress = $null

try {
    $before = Get-QuietShieldSafetySnapshot
    $before | ConvertTo-Json -Depth 10 |
        Set-Content -LiteralPath $preStatePath -Encoding UTF8

    if ([int]$before.QuietShieldServiceCount -ne 0 -or
        @(Get-QuietShieldExactService).Count -ne 0) {
        throw 'The exact QuietShield service already exists; Phase 11C refuses to begin.'
    }

    if (@(Get-NetFirewallRule -Name 'QuietShield.ProgramLock.*' -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'Pre-existing QuietShield Program Lock rules require review before Phase 11C.'
    }

    if (Test-Path -LiteralPath 'D:\QuietShield\Service') {
        throw 'D:\QuietShield\Service already exists before Phase 11C.'
    }

    $resolvedAddresses = @(
        [Net.Dns]::GetHostAddresses('example.com') |
            Where-Object { $_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork } |
            Sort-Object -Property IPAddressToString -Unique
    )

    foreach ($candidateAddress in $resolvedAddresses) {
        $probeBefore = Invoke-Phase11CNetworkProbe `
            -ExecutablePath $targetPath `
            -ProbeAdapter ([string]$selection.probeAdapter) `
            -Address $candidateAddress.ToString() `
            -Port 443 `
            -WorkingDirectory $probeDirectory

        if ([bool]$probeBefore.succeeded) {
            $selectedAddress = $candidateAddress.ToString()
            break
        }
    }

    if ([string]::IsNullOrWhiteSpace([string]$selectedAddress)) {
        throw 'The selected installed application had no reachable literal endpoint before service installation.'
    }

    if (@(Get-Phase11CRunningTargetProcesses -ExecutablePath $targetPath).Count -ne 0) {
        throw 'The selected installed application probe did not exit cleanly before service installation.'
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

    $blockedRequest = Join-Path $evidenceDirectory 'blocked-request.json'
    $blockedResponsePath = Join-Path $evidenceDirectory 'blocked-response.json'

    [pscustomobject][ordered]@{
        approvedRehearsalId = $rehearsalId.ToString('D')
        profileId = 'phase11c.installed-app'
        stableApplicationIdentity = $targetIdentity
        executablePath = $targetPath
        executableSha256 = $targetHash
        policy = 'Blocked'
    } | ConvertTo-Json |
        Set-Content -LiteralPath $blockedRequest -Encoding UTF8

    & 'D:\QuietShield\Service\QuietShield.Service.exe' `
        --control-request $blockedRequest `
        --control-output $blockedResponsePath `
        --pipe-name 'QuietShield.Service.v1'

    if ($LASTEXITCODE -ne 0) {
        throw 'The service refused or failed the Phase 11C installed-application Blocked transaction.'
    }

    $blockedResponse = Get-Content -LiteralPath $blockedResponsePath -Raw | ConvertFrom-Json
    $ruleName = [string]$blockedResponse.Payload.exactRuleName

    if ($ruleName -notmatch '\AQuietShield\.ProgramLock\.[0-9a-f]{32}\z') {
        throw 'The service returned an invalid Phase 11C deterministic rule name.'
    }

    $exactRule = @(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)
    if ($exactRule.Count -ne 1) {
        throw 'The Phase 11C exact QuietShield block rule was not found exactly once.'
    }

    $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $exactRule[0]
    if (-not [string]::Equals([IO.Path]::GetFullPath([string]$appFilter.Program), $targetPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The Phase 11C exact block rule targets a different executable.'
    }

    $probeBlocked = Invoke-Phase11CNetworkProbe `
        -ExecutablePath $targetPath `
        -ProbeAdapter ([string]$selection.probeAdapter) `
        -Address $selectedAddress `
        -Port 443 `
        -WorkingDirectory $probeDirectory

    if ([bool]$probeBlocked.succeeded) {
        throw 'The selected installed application still reached the endpoint while the exact Blocked rule was active.'
    }

    $allowedRequest = Join-Path $evidenceDirectory 'allowed-request.json'
    $allowedResponsePath = Join-Path $evidenceDirectory 'allowed-response.json'

    [pscustomobject][ordered]@{
        approvedRehearsalId = $rehearsalId.ToString('D')
        profileId = 'phase11c.installed-app'
        stableApplicationIdentity = $targetIdentity
        executablePath = $targetPath
        executableSha256 = $targetHash
        policy = 'AllowedOnAll'
    } | ConvertTo-Json |
        Set-Content -LiteralPath $allowedRequest -Encoding UTF8

    & 'D:\QuietShield\Service\QuietShield.Service.exe' `
        --control-request $allowedRequest `
        --control-output $allowedResponsePath `
        --pipe-name 'QuietShield.Service.v1'

    if ($LASTEXITCODE -ne 0) {
        throw 'The service refused or failed the Phase 11C installed-application AllowedOnAll transaction.'
    }

    if (@(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'The exact QuietShield block rule remains after Phase 11C AllowedOnAll.'
    }

    $allowedCommitted = $true

    $probeAllowed = Invoke-Phase11CNetworkProbe `
        -ExecutablePath $targetPath `
        -ProbeAdapter ([string]$selection.probeAdapter) `
        -Address $selectedAddress `
        -Port 443 `
        -WorkingDirectory $probeDirectory

    if (-not [bool]$probeAllowed.succeeded) {
        throw 'Selected installed-application connectivity did not return after AllowedOnAll.'
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
        throw 'Last-known-good status did not recover after the Phase 11C service restart.'
    }

    & (Join-Path $PSScriptRoot 'Stop-QuietShieldService.ps1') `
        -ApprovedServiceStop `
        -Confirm:$false | Write-Output

    & (Join-Path $PSScriptRoot 'Uninstall-QuietShieldService.ps1') `
        -ApprovedServiceUninstall `
        -Confirm:$false | Write-Output

    $serviceInstalled = $false

    if (@(Get-QuietShieldExactService).Count -ne 0) {
        throw 'The exact QuietShield service remains after Phase 11C uninstall.'
    }

    if (@(Get-NetFirewallRule -Name 'QuietShield.ProgramLock.*' -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'A QuietShield Program Lock rule remains after Phase 11C cleanup.'
    }

    if (Test-Path -LiteralPath 'D:\QuietShield\Service') {
        throw 'D:\QuietShield\Service remains after Phase 11C uninstall.'
    }

    if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf) -or
        (Get-QuietShieldFileSha256 -Path $targetPath) -cne $targetHash) {
        throw 'The selected installed application was modified during Phase 11C.'
    }

    $probeAfterCleanup = Invoke-Phase11CNetworkProbe `
        -ExecutablePath $targetPath `
        -ProbeAdapter ([string]$selection.probeAdapter) `
        -Address $selectedAddress `
        -Port 443 `
        -WorkingDirectory $probeDirectory

    if (-not [bool]$probeAfterCleanup.succeeded) {
        throw 'Installed-application connectivity was not restored after Phase 11C service cleanup.'
    }

    $after = Get-QuietShieldSafetySnapshot
    $after | ConvertTo-Json -Depth 10 |
        Set-Content -LiteralPath $postStatePath -Encoding UTF8

    $comparison = Compare-QuietShieldSafetySnapshots -Before $before -After $after
    if (-not [bool]$comparison.PersistentMatch) {
        throw ('Protected Windows state changed during Phase 11C: ' +
            (@($comparison.PersistentDifferences) -join ', '))
    }

    $displayName = [string]$selection.displayName
    $report = @"
# Phase 11C Installed Non-System Application Rehearsal

Status: **Passed**

- Selected installed application: $displayName
- Probe adapter: $([string]$selection.probeAdapter)
- Target identity: Path-derived
- Exact path/SHA-256 binding: Passed
- Pre-existing target processes: 0
- Exact service install/start: Passed
- Installed-service IPC: Passed
- Blocked enforcement against installed application: Passed
- Exact AllowedOnAll rule removal: Passed
- Installed-application connectivity restoration: Passed
- Service restart and last-known-good recovery: Passed
- Exact service stop/uninstall: Passed
- Selected application binary modified: No
- Remaining exact Program Lock rules: 0
- Protected persistent Windows state: Unchanged
- Restart required: No
- Customer-facing enforcement controls enabled: No
- DNS activation: Not attempted
- Network-specific enforcement: Not attempted

The selected application was explicitly approved locally and remained bound to one exact executable path, one SHA-256, one path-derived `windows-exe:` identity, and one rehearsal ID. QuietShield did not modify or uninstall the selected application.

No Windows system executable, browser session, QuietShield executable, DNS setting, WFP setting, adapter setting, unrelated Firewall rule, startup item, certificate, or unrelated security setting was changed.
"@

    $utf8NoBom = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText(
        $reportPath,
        $report.Replace("`r`n","`n").Replace("`r","`n").TrimEnd("`n") + "`n",
        $utf8NoBom)

    [pscustomobject][ordered]@{
        status = 'Passed'
        selectedApplication = [string]$selection.displayName
        executablePath = $targetPath
        executableSha256 = $targetHash
        stableIdentity = $targetIdentity
        probeAdapter = [string]$selection.probeAdapter
        endpointAddress = $selectedAddress
        exactRuleName = $ruleName
        blocked = 'Passed'
        allowedOnAllRemoval = 'Passed'
        connectivityRestored = $true
        lastKnownGoodRecovered = $true
        serviceAbsent = $true
        installRootAbsent = $true
        remainingProgramLockRules = 0
        targetBinaryModified = $false
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
            if (-not $allowedCommitted) {
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
            Write-Error ('Exact Phase 11C emergency cleanup also failed: ' + $_.Exception.Message)
        }
    }

    throw $primaryFailure
}
finally {
    Stop-QuietShieldLog
}
