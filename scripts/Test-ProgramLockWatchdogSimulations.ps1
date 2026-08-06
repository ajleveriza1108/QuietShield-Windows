[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ProgramLockRehearsal.Script.Common.ps1')

Assert-QuietShieldPowerShell51
Assert-QuietShieldNonElevated

function Assert-QuietShieldSimulation {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) { throw $Message }
}

$utcDateTime = [DateTime]::SpecifyKind([DateTime]::ParseExact(
    '2026-08-06T06:31:07.1234567',
    'yyyy-MM-ddTHH:mm:ss.fffffff',
    [Globalization.CultureInfo]::InvariantCulture), [DateTimeKind]::Utc)
$utcResult = ConvertTo-QuietShieldUtcDateTimeOffset -Value $utcDateTime
Assert-QuietShieldSimulation -Condition ($utcResult.Offset -eq [TimeSpan]::Zero -and $utcResult.UtcDateTime.Ticks -eq $utcDateTime.Ticks) -Message 'UTC DateTime conversion lost kind or sub-second precision.'

$localDateTime = [DateTime]::SpecifyKind($utcDateTime.ToLocalTime(), [DateTimeKind]::Local)
$localExpected = ([DateTimeOffset]$localDateTime).ToUniversalTime()
$localResult = ConvertTo-QuietShieldUtcDateTimeOffset -Value $localDateTime
Assert-QuietShieldSimulation -Condition ($localResult.Offset -eq [TimeSpan]::Zero -and $localResult.UtcDateTime.Ticks -eq $localExpected.UtcDateTime.Ticks) -Message 'Local DateTime conversion did not produce the exact UTC instant.'

$unspecifiedDateTime = [DateTime]::SpecifyKind($utcDateTime, [DateTimeKind]::Unspecified)
$unspecifiedResult = ConvertTo-QuietShieldUtcDateTimeOffset -Value $unspecifiedDateTime
Assert-QuietShieldSimulation -Condition ($unspecifiedResult.Offset -eq [TimeSpan]::Zero -and $unspecifiedResult.UtcDateTime.Ticks -eq $unspecifiedDateTime.Ticks) -Message 'Unspecified DateTime was not treated as an explicit UTC value.'

$deadline = [DateTimeOffset]::ParseExact('2026-08-06T06:32:02.4000000Z', 'O', [Globalization.CultureInfo]::InvariantCulture)
$current = [DateTimeOffset]::ParseExact('2026-08-06T06:32:02.5000000Z', 'O', [Globalization.CultureInfo]::InvariantCulture)
$deadlineTrigger = Get-QuietShieldProgramLockWatchdogTrigger -RuleCreated $true -ParentAlive $true -CurrentTime $current -Deadline $deadline `
    -RollbackRequested $false -VerificationFailed $false -ProbeFailed $false -HeartbeatExists $false
Assert-QuietShieldSimulation -Condition ($deadlineTrigger -ceq 'DeadlineExpired') -Message 'The watchdog did not trigger exact cleanup at the sub-second deadline.'

$heartbeatTrigger = Get-QuietShieldProgramLockWatchdogTrigger -RuleCreated $true -ParentAlive $true -CurrentTime $current -Deadline $current.AddMinutes(1) `
    -RollbackRequested $false -VerificationFailed $false -ProbeFailed $false -HeartbeatExists $true -HeartbeatLastWriteTime $current.AddSeconds(-9)
Assert-QuietShieldSimulation -Condition ($heartbeatTrigger -ceq 'HeartbeatLost') -Message 'The watchdog did not trigger cleanup after heartbeat loss.'

$parentTrigger = Get-QuietShieldProgramLockWatchdogTrigger -RuleCreated $true -ParentAlive $false -CurrentTime $current -Deadline $current.AddMinutes(1) `
    -RollbackRequested $false -VerificationFailed $false -ProbeFailed $false -HeartbeatExists $true -HeartbeatLastWriteTime $current
Assert-QuietShieldSimulation -Condition ($parentTrigger -ceq 'ParentProcessLost') -Message 'The watchdog did not trigger cleanup after orchestrator loss.'

$healthyTrigger = Get-QuietShieldProgramLockWatchdogTrigger -RuleCreated $true -ParentAlive $true -CurrentTime $current -Deadline $current.AddMinutes(1) `
    -RollbackRequested $false -VerificationFailed $false -ProbeFailed $false -HeartbeatExists $true -HeartbeatLastWriteTime $current
Assert-QuietShieldSimulation -Condition ($null -eq $healthyTrigger) -Message 'The watchdog triggered during a healthy observation.'

function New-QuietShieldSimulatedSafetySnapshot {
    param(
        [string]$DnsHash = 'DNS-A',
        [string]$AdapterConfigurationHash = 'ADAPTER-CONFIG-A',
        [string]$AdapterStatus = 'Disconnected',
        [string]$QuietShieldFirewallRuleHash = 'RULES-A'
    )

    return [pscustomobject]@{
        QuietShieldServiceHash = 'SERVICES-A'
        FirewallHash = 'FIREWALL-A'
        QuietShieldFirewallRuleHash = $QuietShieldFirewallRuleHash
        DnsHash = $DnsHash
        AdapterIdentityHash = 'ADAPTER-IDENTITY-A'
        AdapterConfigurationHash = $AdapterConfigurationHash
        StartupHash = 'STARTUP-A'
        QuietShieldWfpHash = 'WFP-A'
        QuietShieldRegistryHash = 'REGISTRY-A'
        AdapterOperationalState = @([pscustomobject]@{
            InterfaceGuid = '11111111-1111-1111-1111-111111111111'
            InterfaceIndex = 10
            Name = 'OpenVPN Data Channel Offload for Surfshark'
            InterfaceDescription = 'OpenVPN Data Channel Offload'
            Status = $AdapterStatus
        })
    }
}

$baseline = New-QuietShieldSimulatedSafetySnapshot
$vpnTransition = New-QuietShieldSimulatedSafetySnapshot -AdapterStatus 'Up'
$vpnComparison = Compare-QuietShieldSafetySnapshots -Before $baseline -After $vpnTransition
Assert-QuietShieldSimulation -Condition ([bool]$vpnComparison.PersistentMatch) -Message 'A volatile VPN Up/Down transition was incorrectly classified as persistent configuration.'
Assert-QuietShieldSimulation -Condition ($vpnComparison.AdapterOperationalEvents.Count -eq 1 -and [string]$vpnComparison.AdapterOperationalEvents[0].Classification -ceq 'VpnOrVirtual') -Message 'The VPN operational transition was not recorded as an environmental event.'

$adapterConfigurationChange = New-QuietShieldSimulatedSafetySnapshot -AdapterConfigurationHash 'ADAPTER-CONFIG-B'
$adapterComparison = Compare-QuietShieldSafetySnapshots -Before $baseline -After $adapterConfigurationChange
Assert-QuietShieldSimulation -Condition (-not [bool]$adapterComparison.PersistentMatch -and @($adapterComparison.PersistentDifferences) -contains 'AdapterConfigurationHash') -Message 'A persistent adapter configuration change was not rejected.'

$dnsChange = New-QuietShieldSimulatedSafetySnapshot -DnsHash 'DNS-B'
$dnsComparison = Compare-QuietShieldSafetySnapshots -Before $baseline -After $dnsChange
Assert-QuietShieldSimulation -Condition (-not [bool]$dnsComparison.PersistentMatch -and @($dnsComparison.PersistentDifferences) -contains 'DnsHash') -Message 'A DNS configuration change was not rejected.'

$ruleChange = New-QuietShieldSimulatedSafetySnapshot -QuietShieldFirewallRuleHash 'RULES-B'
$ruleComparison = Compare-QuietShieldSafetySnapshots -Before $baseline -After $ruleChange
Assert-QuietShieldSimulation -Condition (-not [bool]$ruleComparison.PersistentMatch -and @($ruleComparison.PersistentDifferences) -contains 'QuietShieldFirewallRuleHash') -Message 'A QuietShield-owned Firewall rule change was not rejected.'

$restoreSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Restore-ProgramLockRehearsal.ps1') -Raw
$watchdogSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Watch-ProgramLockFirewallRehearsal.ps1') -Raw
$removeCommandName = 'Remove-Net' + 'FirewallRule'
$exactRemovalText = $removeCommandName + ' -Name ([string]$state.rule.name) -Confirm:$false'
Assert-QuietShieldSimulation -Condition ($restoreSource.Contains($exactRemovalText)) -Message 'Exact-rule removal is missing.'
Assert-QuietShieldSimulation -Condition (-not $restoreSource.Contains($removeCommandName + ' -DisplayName')) -Message 'Cleanup uses prohibited display-name matching.'
Assert-QuietShieldSimulation -Condition (-not [Text.RegularExpressions.Regex]::IsMatch($restoreSource, [Text.RegularExpressions.Regex]::Escape($removeCommandName) + '[^\r\n]*\*', [Text.RegularExpressions.RegexOptions]::IgnoreCase)) -Message 'Cleanup uses a broad wildcard removal.'
Assert-QuietShieldSimulation -Condition ($watchdogSource.Contains('-ApprovedWatchdogCleanup')) -Message 'The watchdog does not use the dedicated cleanup approval switch.'
Assert-QuietShieldSimulation -Condition (-not $watchdogSource.Contains('-Confirm:$false')) -Message 'The watchdog passes Confirm through powershell.exe -File.'
Assert-QuietShieldSimulation -Condition ($restoreSource.Contains('[switch]$ApprovedWatchdogCleanup')) -Message 'The restore script does not declare the dedicated watchdog approval switch.'

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('QuietShield-Phase9-WatchdogTests-' + [Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $temporaryRoot)
try {
    $transactionId = [Guid]::NewGuid()
    $createdAt = [DateTimeOffset]::UtcNow
    $statePath = Join-Path $temporaryRoot 'state.json'
    $probePath = Join-Path $temporaryRoot 'QuietShield.ConnectionProbe.exe'
    $description = New-QuietShieldProgramLockRehearsalDescription -TransactionId $transactionId
    $state = [pscustomobject][ordered]@{
        schemaVersion = 1; productMarker = 'QuietShield'; purpose = 'ProgramLockFirewallRehearsal'; transactionId = $transactionId.ToString('D');
        createdAtUtc = $createdAt.ToString('O'); expiresAtUtc = $createdAt.AddSeconds(15).ToString('O'); durationSeconds = 15; state = 'Prepared'; completed = $false;
        firewallServiceHealthy = $true; baseFilteringEngineHealthy = $true; existingOwnedRehearsalRuleNames = @(); firewallProfiles = @();
        rule = [pscustomobject][ordered]@{
            ownershipMarker = 'QuietShield'; schemaVersion = 1; name = ('QuietShield.ProgramLock.Rehearsal.' + $transactionId.ToString('D'));
            description = $description; programPath = $probePath; direction = 'Outbound'; action = 'Block'; enabled = $true; profile = 'Any'; protocol = 'TCP';
            remoteAddress = '192.0.2.1'; remotePort = 443; localAddress = 'Any'; localPort = 'Any'; edgeTraversal = 'Block'
        };
        payloadSha256 = ''
    }
    [void](Set-QuietShieldProgramLockRehearsalState -State $state -StatePath $statePath -NewState 'RehearsalActive')

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $approvalOutput = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Restore-ProgramLockRehearsal.ps1') -StatePath $statePath 2>&1)
        $approvalExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    Assert-QuietShieldSimulation -Condition ($approvalExitCode -ne 0 -and ($approvalOutput -join ' ').Contains('ApprovedWatchdogCleanup')) -Message 'Restore did not refuse cleanup without its explicit approval switch.'

    '{ malformed' | Set-Content -LiteralPath $statePath -Encoding UTF8
    $malformedRefused = $false
    try { [void](Test-QuietShieldProgramLockRehearsalState -StatePath $statePath) }
    catch { $malformedRefused = $true }
    Assert-QuietShieldSimulation -Condition $malformedRefused -Message 'Malformed rehearsal state was accepted.'

    $state.productMarker = 'Foreign'
    [void](Set-QuietShieldProgramLockRehearsalState -State $state -StatePath $statePath -NewState 'RehearsalActive')
    $foreignRefused = $false
    try { [void](Test-QuietShieldProgramLockRehearsalState -StatePath $statePath) }
    catch { $foreignRefused = $true }
    Assert-QuietShieldSimulation -Condition $foreignRefused -Message 'Foreign rehearsal ownership was accepted.'

    $evidencePath = Join-Path $temporaryRoot 'watchdog-evidence.jsonl'
    $ruleName = 'QuietShield.ProgramLock.Rehearsal.' + $transactionId.ToString('D')
    Add-QuietShieldProgramLockRehearsalEvidence -EvidencePath $evidencePath -Entry ([ordered]@{
        schemaVersion = 1; productMarker = 'QuietShield'; purpose = 'ProgramLockFirewallRehearsalEvidence'; transactionId = $transactionId.ToString('D');
        event = 'WatchdogRollbackTriggered'; trigger = 'DeadlineExpired'; timestampUtc = $createdAt.AddSeconds(15).ToString('O')
    })
    Add-QuietShieldProgramLockRehearsalEvidence -EvidencePath $evidencePath -Entry ([ordered]@{
        schemaVersion = 1; productMarker = 'QuietShield'; purpose = 'ProgramLockFirewallRehearsalEvidence'; transactionId = $transactionId.ToString('D');
        event = 'ExactRuleRemoved'; ruleName = $ruleName; timestampUtc = $createdAt.AddSeconds(16).ToString('O')
    })
    Add-QuietShieldProgramLockRehearsalEvidence -EvidencePath $evidencePath -Entry ([ordered]@{
        schemaVersion = 1; productMarker = 'QuietShield'; purpose = 'ProgramLockFirewallRehearsalEvidence'; transactionId = $transactionId.ToString('D');
        event = 'WatchdogStoppedAfterVerifiedCleanup'; timestampUtc = $createdAt.AddSeconds(17).ToString('O')
    })
    $completionEvidence = Test-QuietShieldProgramLockWatchdogCompletionEvidence -EvidencePath $evidencePath -TransactionId $transactionId -RuleName $ruleName
    Assert-QuietShieldSimulation -Condition ([bool]$completionEvidence.Valid) -Message 'Valid watchdog completion evidence was refused.'
}
finally {
    $temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $resolvedTemporaryRoot = [IO.Path]::GetFullPath($temporaryRoot)
    if (-not $resolvedTemporaryRoot.StartsWith($temporaryBase, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolvedTemporaryRoot) -notlike 'QuietShield-Phase9-WatchdogTests-*') {
        throw 'Refused to remove an unexpected watchdog simulation directory.'
    }
    if (Test-Path -LiteralPath $resolvedTemporaryRoot) { Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force }
}

$successfulProcess = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Milliseconds 400; exit 0') -WindowStyle Hidden -PassThru
$exitCodeUnavailable = $false
try {
    $prematureExitCode = $successfulProcess.ExitCode
    if ($null -eq $prematureExitCode) { $exitCodeUnavailable = $true }
}
catch [InvalidOperationException] { $exitCodeUnavailable = $true }
Assert-QuietShieldSimulation -Condition $exitCodeUnavailable -Message 'ExitCode unexpectedly became available before process exit.'
$successfulWait = $successfulProcess.WaitForExit(5000)
$successfulProcess.Refresh()
Assert-QuietShieldSimulation -Condition ($successfulWait -and $successfulProcess.HasExited -and [int]$successfulProcess.ExitCode -eq 0) -Message 'Successful process exit was not accepted after bounded WaitForExit and Refresh.'
$successfulProcess.Dispose()

$timeoutProcess = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Milliseconds 800; exit 0') -WindowStyle Hidden -PassThru
$boundedWait = $timeoutProcess.WaitForExit(50)
$timeoutProcess.Refresh()
Assert-QuietShieldSimulation -Condition (-not $boundedWait -and -not $timeoutProcess.HasExited) -Message 'The bounded process-exit timeout was not reported accurately.'
Assert-QuietShieldSimulation -Condition ($timeoutProcess.WaitForExit(5000)) -Message 'The timeout simulation process did not exit naturally.'
$timeoutProcess.Refresh()
$timeoutProcess.Dispose()

$nonzeroProcess = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-Command', 'exit 7') -WindowStyle Hidden -PassThru
Assert-QuietShieldSimulation -Condition ($nonzeroProcess.WaitForExit(5000)) -Message 'The nonzero-exit simulation process timed out.'
$nonzeroProcess.Refresh()
Assert-QuietShieldSimulation -Condition ($nonzeroProcess.HasExited -and [int]$nonzeroProcess.ExitCode -eq 7) -Message 'A nonzero watchdog exit was not preserved.'
$nonzeroProcess.Dispose()

$invokeSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Invoke-ProgramLockFirewallRehearsal.ps1') -Raw
Assert-QuietShieldSimulation -Condition ($invokeSource.Contains("Get-NetFirewallRule -Name 'QuietShield.ProgramLock.Rehearsal.*'")) -Message 'The zero-remaining-rehearsal-rule check is missing.'
Assert-QuietShieldSimulation -Condition ($invokeSource.Contains('$watchdog.WaitForExit(15000)') -and $invokeSource.Contains('$watchdog.Refresh()') -and $invokeSource.Contains('$watchdog.HasExited')) -Message 'The production watchdog process-exit sequence is incomplete.'

[pscustomobject][ordered]@{
    status = 'Passed'
    utcDateTimeConversion = 'Passed'
    localDateTimeConversion = 'Passed'
    unspecifiedDateTimeConversion = 'PassedAsUtc'
    subSecondDeadlineCleanup = 'Passed'
    heartbeatLossCleanup = 'Passed'
    orchestratorLossCleanup = 'Passed'
    vpnOperationalTransitionReporting = 'Passed'
    persistentAdapterConfigurationValidation = 'Passed'
    dnsConfigurationValidation = 'Passed'
    quietShieldFirewallRuleValidation = 'Passed'
    explicitWatchdogApprovalRequired = 'Passed'
    malformedTransactionRefused = 'Passed'
    foreignTransactionRefused = 'Passed'
    exitCodeUnavailableBeforeExit = 'Passed'
    successfulExitAfterBoundedWait = 'Passed'
    boundedProcessExitTimeout = 'Passed'
    validWatchdogCleanupEvidence = 'Passed'
    nonzeroWatchdogExit = 'Passed'
    zeroRemainingRehearsalRules = 'Passed'
    exactRuleRemovalOnly = 'Passed'
} | ConvertTo-Json -Depth 5
