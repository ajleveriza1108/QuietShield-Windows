[CmdletBinding()]
param(
    [switch]$ApprovedTemporaryFirewallRehearsal,
    [switch]$DryRun,
    [switch]$PreflightOnly,
    [ValidateRange(1, 120)][int]$DurationSeconds = 15,
    [string]$OutputPath = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ProgramLockRehearsal.Script.Common.ps1')

Assert-QuietShieldPowerShell51
$root = Get-QuietShieldRepositoryRoot
if ($DryRun -and $PreflightOnly) { throw 'DryRun and PreflightOnly cannot be combined.' }
if ($DryRun -or $PreflightOnly) { Assert-QuietShieldNonElevated }
else {
    if (-not $ApprovedTemporaryFirewallRehearsal) { throw 'The real rehearsal requires -ApprovedTemporaryFirewallRehearsal.' }
    if (-not (Test-QuietShieldAdministrator)) { throw 'The real rehearsal requires an already elevated Administrator console and never self-elevates.' }
    if ($DurationSeconds -ne 15) { throw 'The approved real Phase 9 rehearsal duration is exactly 15 seconds.' }
    $currentVpnState = @(Get-QuietShieldVpnAndVirtualAdapterOperationalState)
    Assert-QuietShieldSurfsharkAndOpenVpnDisconnected -OperationalState $currentVpnState
}

$probePath = Join-Path $root 'artifacts\bin\QuietShield.ConnectionProbe\x64\Release\net10.0\QuietShield.ConnectionProbe.exe'
if (-not (Test-Path -LiteralPath $probePath -PathType Leaf)) { throw ('The dedicated Release probe executable was not found: ' + $probePath) }
$probePath = (Resolve-Path -LiteralPath $probePath).Path
$firewallService = Get-Service -Name 'MpsSvc' -ErrorAction Stop
$bfeService = Get-Service -Name 'BFE' -ErrorAction Stop
if ([string]$firewallService.Status -cne 'Running' -or [string]$bfeService.Status -cne 'Running') { throw 'Windows Firewall or Base Filtering Engine is not healthy.' }
$profiles = @(Get-NetFirewallProfile | Sort-Object -Property Name | ForEach-Object {
    [ordered]@{ name = [string]$_.Name; enabled = [bool]$_.Enabled; defaultInboundAction = [string]$_.DefaultInboundAction; defaultOutboundAction = [string]$_.DefaultOutboundAction }
})
$existing = @(Get-NetFirewallRule -Name 'QuietShield.ProgramLock.Rehearsal.*' -ErrorAction SilentlyContinue)
if ($existing.Count -ne 0) { throw 'A prior QuietShield rehearsal rule exists; concurrent or stale rehearsal requires review before any new attempt.' }

$vpnStability = $null
if ($PreflightOnly) {
    $vpnStability = Test-QuietShieldVpnAndVirtualAdapterStability -DurationSeconds 15
}

$resolvedAddresses = @([Net.Dns]::GetHostAddresses('example.com') | Sort-Object -Property AddressFamily,IPAddressToString -Unique)
if ($resolvedAddresses.Count -eq 0) { throw 'example.com did not resolve during read-only preflight.' }
$selectedAddress = $null
foreach ($candidate in $resolvedAddresses) {
    & $probePath $candidate.ToString() '443' '5000' | Write-Output
    if ($LASTEXITCODE -eq 0) { $selectedAddress = $candidate; break }
}
if ($null -eq $selectedAddress) { throw 'No resolved example.com endpoint was reachable on TCP port 443; no Firewall change was made.' }

if ($PreflightOnly) {
    [pscustomobject][ordered]@{
        status = 'PreflightPassed'
        durationSeconds = [int]$vpnStability.DurationSeconds
        vpnAndVirtualAdaptersStable = [bool]$vpnStability.Stable
        surfsharkOpenVpnDisconnected = [bool]$vpnStability.SurfsharkOpenVpnDisconnected
        vpnAndVirtualAdapterStateHash = [string]$vpnStability.StateHash
        exactRehearsalRuleCount = $existing.Count
        endpoint = ($selectedAddress.ToString() + ':443')
        probePreBlockExitCode = 0
        administrator = $false
    } | ConvertTo-Json -Depth 6
    return
}

$transactionId = [Guid]::NewGuid()
$createdAt = [DateTimeOffset]::UtcNow
$expiresAt = $createdAt.AddSeconds($DurationSeconds)
$ruleName = 'QuietShield.ProgramLock.Rehearsal.' + $transactionId.ToString('D')
$description = New-QuietShieldProgramLockRehearsalDescription -TransactionId $transactionId
$state = [pscustomobject][ordered]@{
    schemaVersion = 1; productMarker = 'QuietShield'; purpose = 'ProgramLockFirewallRehearsal'; transactionId = $transactionId.ToString('D');
    createdAtUtc = $createdAt.ToString('O'); expiresAtUtc = $expiresAt.ToString('O'); durationSeconds = $DurationSeconds; state = 'Prepared'; completed = $false;
    firewallServiceHealthy = $true; baseFilteringEngineHealthy = $true; existingOwnedRehearsalRuleNames = @($existing | ForEach-Object { [string]$_.Name });
    firewallProfiles = $profiles;
    rule = [pscustomobject][ordered]@{
        ownershipMarker = 'QuietShield'; schemaVersion = 1; name = $ruleName; description = $description; programPath = $probePath;
        direction = 'Outbound'; action = 'Block'; enabled = $true; profile = 'Any'; protocol = 'TCP'; remoteAddress = $selectedAddress.ToString();
        remotePort = 443; localAddress = 'Any'; localPort = 'Any'; edgeTraversal = 'Block'
    };
    payloadSha256 = ''
}

if ($DryRun) {
    if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $root ('logs\phase9-firewall-dry-run-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json') }
    [void](Set-QuietShieldProgramLockRehearsalState -State $state -StatePath $OutputPath -NewState 'WatchdogStarted')
    [pscustomobject]@{
        status = 'DryValidationPassed'; statePath = [IO.Path]::GetFullPath($OutputPath); endpoint = ($selectedAddress.ToString() + ':443');
        probePreBlockExitCode = 0; transactionValidated = $true; watchdogSimulation = $true; firewallRuleCreated = $false; administrator = $false
    } | ConvertTo-Json -Depth 6
    return
}

$working = Join-Path $root ('artifacts\program-lock-rehearsal\' + $transactionId.ToString('D'))
[void](New-Item -ItemType Directory -Path $working -Force)
$statePath = Join-Path $working 'state.json'
$evidencePath = Join-Path $root 'artifacts\program-lock-rehearsal\attempts.jsonl'
$heartbeatPath = Join-Path $working 'heartbeat.txt'
$rollbackRequestPath = Join-Path $working 'rollback-requested.txt'
$verificationFailurePath = Join-Path $working 'verification-failed.txt'
$probeFailurePath = Join-Path $working 'probe-failed.txt'
$stopPath = Join-Path $working 'stop-watchdog.txt'
$watchdogLog = Join-Path $working 'watchdog.log'
$watchdogScript = Join-Path $PSScriptRoot 'Watch-ProgramLockFirewallRehearsal.ps1'
$restoreScript = Join-Path $PSScriptRoot 'Restore-ProgramLockRehearsal.ps1'
$ruleCreated = $false
$preSafetySnapshot = Get-QuietShieldSafetySnapshot

try {
    [void](Set-QuietShieldProgramLockRehearsalState -State $state -StatePath $statePath -NewState 'EndpointVerified')
    [void](Set-QuietShieldProgramLockRehearsalState -State $state -StatePath $statePath -NewState 'BackupCreated')
    Add-QuietShieldProgramLockRehearsalEvidence -EvidencePath $evidencePath -Entry ([ordered]@{
        schemaVersion = 1; productMarker = 'QuietShield'; purpose = 'ProgramLockFirewallRehearsalEvidence'; transactionId = $transactionId.ToString('D');
        event = 'ApprovedAttemptPrepared'; ruleName = $ruleName; endpoint = ($selectedAddress.ToString() + ':443'); timestampUtc = $createdAt.ToString('O'); payloadSha256 = [string]$state.payloadSha256
    })
    $watchdogArguments = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $watchdogScript + '"'),'-StatePath',('"' + $statePath + '"'),
        '-OrchestratorProcessId',[string]$PID,'-HeartbeatPath',('"' + $heartbeatPath + '"'),'-RollbackRequestPath',('"' + $rollbackRequestPath + '"'),
        '-VerificationFailurePath',('"' + $verificationFailurePath + '"'),'-ProbeFailurePath',('"' + $probeFailurePath + '"'),'-StopPath',('"' + $stopPath + '"'),'-EvidencePath',('"' + $evidencePath + '"'))
    $watchdog = Start-Process -FilePath 'powershell.exe' -ArgumentList $watchdogArguments -WindowStyle Hidden -RedirectStandardOutput $watchdogLog -RedirectStandardError ($watchdogLog + '.err') -PassThru
    [void](Set-QuietShieldProgramLockRehearsalState -State $state -StatePath $statePath -NewState 'WatchdogStarted')
    Start-Sleep -Milliseconds 750
    if ($watchdog.HasExited) { throw 'The independent watchdog exited before rule creation.' }
    $currentVpnState = @(Get-QuietShieldVpnAndVirtualAdapterOperationalState)
    Assert-QuietShieldSurfsharkAndOpenVpnDisconnected -OperationalState $currentVpnState

    [void](Test-QuietShieldProgramLockRehearsalDescription -Description $description -TransactionId $transactionId)
    New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Description $description -Direction Outbound -Action Block -Enabled True -Profile Any -Program $probePath -Protocol TCP -RemoteAddress $selectedAddress.ToString() -RemotePort 443 -LocalAddress Any -LocalPort Any -EdgeTraversalPolicy Block | Out-Null
    $ruleCreated = $true
    [void](Set-QuietShieldProgramLockRehearsalState -State $state -StatePath $statePath -NewState 'RuleCreated')
    $rule = Get-QuietShieldExactProgramLockRehearsalRule -RuleName $ruleName
    if ($null -eq $rule) { [void](New-Item -ItemType File -Path $verificationFailurePath -Force); throw 'The exact rehearsal rule was not found after creation.' }
    [void](Test-QuietShieldExactProgramLockRehearsalRuleProperties -State $state -Rule $rule)
    [void](Set-QuietShieldProgramLockRehearsalState -State $state -StatePath $statePath -NewState 'RuleVerified')
    & $probePath $selectedAddress.ToString() '443' '5000' | Write-Output
    if ($LASTEXITCODE -ne 10) { [void](New-Item -ItemType File -Path $probeFailurePath -Force); throw ('The blocked probe returned unexpected exit code ' + [string]$LASTEXITCODE) }
    [void](Set-QuietShieldProgramLockRehearsalState -State $state -StatePath $statePath -NewState 'BlockVerified')
    [void](Set-QuietShieldProgramLockRehearsalState -State $state -StatePath $statePath -NewState 'RehearsalActive')
    while ((ConvertTo-QuietShieldUtcDateTimeOffset -Value ([DateTimeOffset]::UtcNow)) -lt (ConvertTo-QuietShieldUtcDateTimeOffset -Value $expiresAt)) {
        [DateTimeOffset]::UtcNow.ToString('O') | Set-Content -LiteralPath $heartbeatPath -Encoding ASCII
        Start-Sleep -Seconds 1
    }
    $watchdogExited = $watchdog.WaitForExit(15000)
    $watchdog.Refresh()
    if (-not $watchdogExited -and -not $watchdog.HasExited) { throw ('Watchdog did not exit within the bounded cleanup timeout. Process ID: ' + [string]$watchdog.Id) }
    if (-not $watchdog.HasExited) { throw ('Watchdog process exit could not be verified after the bounded cleanup wait. Process ID: ' + [string]$watchdog.Id) }
    $watchdogExitCode = [int]$watchdog.ExitCode
    if ($watchdogExitCode -ne 0) { throw ('Watchdog deadline cleanup returned exit code ' + [string]$watchdogExitCode) }
    $watchdogEvidence = Test-QuietShieldProgramLockWatchdogCompletionEvidence -EvidencePath $evidencePath -TransactionId $transactionId -RuleName $ruleName
    if (-not [bool]$watchdogEvidence.Valid) { throw 'Watchdog completion evidence did not validate.' }
    $state = (Test-QuietShieldProgramLockRehearsalState -StatePath $statePath -AllowCompleted).State
    if ([string]$state.state -cne 'RuleRemoved') { throw ('Watchdog did not record exact deadline cleanup. State: ' + [string]$state.state) }
    if ($null -ne (Get-QuietShieldExactProgramLockRehearsalRule -RuleName $ruleName)) { throw 'The exact rehearsal rule remains after watchdog deadline cleanup.' }
    $ruleCreated = $false
    & $probePath $selectedAddress.ToString() '443' '5000' | Write-Output
    if ($LASTEXITCODE -ne 0) { throw 'Probe connectivity was not restored after exact rule removal.' }
    [void](Set-QuietShieldProgramLockRehearsalState -State $state -StatePath $statePath -NewState 'ConnectivityRestored')
    $postSafetySnapshot = Get-QuietShieldSafetySnapshot
    $safetyComparison = Compare-QuietShieldSafetySnapshots -Before $preSafetySnapshot -After $postSafetySnapshot
    foreach ($environmentalEvent in @($safetyComparison.AdapterOperationalEvents)) {
        Add-QuietShieldProgramLockRehearsalEvidence -EvidencePath $evidencePath -Entry ([ordered]@{
            schemaVersion = 1; productMarker = 'QuietShield'; purpose = 'ProgramLockFirewallRehearsalEvidence'; transactionId = $transactionId.ToString('D');
            event = [string]$environmentalEvent.Event; interfaceGuid = [string]$environmentalEvent.InterfaceGuid; interfaceIndex = [int]$environmentalEvent.InterfaceIndex;
            adapterName = [string]$environmentalEvent.AdapterName; classification = [string]$environmentalEvent.Classification;
            beforeStatus = [string]$environmentalEvent.BeforeStatus; afterStatus = [string]$environmentalEvent.AfterStatus; timestampUtc = [DateTimeOffset]::UtcNow.ToString('O')
        })
    }
    if (-not [bool]$safetyComparison.PersistentMatch) {
        throw ('Persistent protected Windows state changed during the rehearsal: ' + (@($safetyComparison.PersistentDifferences) -join ', '))
    }
    $remainingOwnedRules = @(Get-NetFirewallRule -Name 'QuietShield.ProgramLock.Rehearsal.*' -ErrorAction SilentlyContinue)
    if ($remainingOwnedRules.Count -ne 0) { throw 'One or more QuietShield rehearsal rules remain after watchdog cleanup.' }
    [void](Set-QuietShieldProgramLockRehearsalState -State $state -StatePath $statePath -NewState 'Completed' -Completed $true)
}
catch {
    if ($ruleCreated) {
        [void](New-Item -ItemType File -Path $rollbackRequestPath -Force)
        try { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $restoreScript -StatePath $statePath -ApprovedOrchestratorRollback -EvidencePath $evidencePath }
        catch { Write-Error ('Emergency exact rollback also failed: ' + $_.Exception.Message) }
    }
    throw
}
