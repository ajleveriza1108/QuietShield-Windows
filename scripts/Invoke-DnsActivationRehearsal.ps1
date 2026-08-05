[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [switch]$ApprovedTemporaryActivation,
    [ValidateRange(1, 300)]
    [int]$DurationSeconds = 180
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'DnsTransaction.Script.Common.ps1')

Assert-QuietShieldPowerShell51
if (-not $ApprovedTemporaryActivation) { throw 'The explicit -ApprovedTemporaryActivation switch is required.' }
if (-not (Test-QuietShieldAdministrator)) { throw 'The approved temporary DNS rehearsal requires Administrator rights. This script never self-elevates or bypasses UAC.' }
if ($DurationSeconds -gt 300) { throw 'The rehearsal duration cannot exceed 300 seconds.' }

$root = Get-QuietShieldRepositoryRoot
$mutex = New-Object System.Threading.Mutex($false, 'Global\QuietShieldDnsActivationRehearsal')
$mutexAcquired = $false
$hostProcess = $null
$watchdogProcess = $null
$rollbackArmed = $false
$dnsChanged = $false
$restorationVerified = $false
$attemptStartRecorded = $false
$stateName = 'Prepared'
$allowedStateTransitions = @{
    Prepared = @('WatchdogStarted')
    WatchdogStarted = @('ResolverStarted')
    ResolverStarted = @('DnsChanged')
    DnsChanged = @('VerificationPassed', 'RollbackStarted')
    VerificationPassed = @('RehearsalActive', 'RollbackStarted')
    RehearsalActive = @('RollbackStarted')
    RollbackStarted = @('DnsRestored')
    DnsRestored = @('PostRestoreVerified')
    PostRestoreVerified = @('Completed')
    Completed = @()
}
$rehearsalId = [Guid]'9d5c7c5e-0b17-4b9a-b474-5d8db24e2e01'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$evidenceRoot = Join-Path $root ('artifacts\dns-rehearsal\' + $timestamp + '-' + $rehearsalId.ToString('N'))
$attemptRecordsPath = Join-Path $root 'artifacts\dns-rehearsal\attempt-records.jsonl'
$statePath = Join-Path $evidenceRoot 'state.json'
$timelinePath = Join-Path $evidenceRoot 'timeline.jsonl'
$backupPath = Join-Path $evidenceRoot 'original-dns-backup.json'
$armedPath = Join-Path $evidenceRoot 'rollback-armed.marker'
$rollbackRequestPath = Join-Path $evidenceRoot 'rollback-request.marker'
$restoredPath = Join-Path $evidenceRoot 'dns-restored.json'
$hostReadyPath = Join-Path $evidenceRoot 'host-ready.json'
$heartbeatPath = Join-Path $evidenceRoot 'host-heartbeat.json'
$hostStopPath = Join-Path $evidenceRoot 'host-stop.marker'
$cancelPath = Join-Path $evidenceRoot 'watchdog-cancel.marker'
$hostLogPath = Join-Path $evidenceRoot 'host.log.jsonl'
$watchdogLogPath = Join-Path $evidenceRoot 'watchdog.log.jsonl'
$resultPath = Join-Path $evidenceRoot 'rehearsal-result.json'
$preSnapshotPath = Join-Path $evidenceRoot 'pre-state.json'
$postSnapshotPath = Join-Path $evidenceRoot 'post-state.json'
$preUdpProbePath = Join-Path $evidenceRoot 'pre-change-blocked-udp.json'
$preTcpProbePath = Join-Path $evidenceRoot 'pre-change-blocked-tcp.json'
$activeUdpProbePath = Join-Path $evidenceRoot 'active-blocked-udp.json'
$activeTcpProbePath = Join-Path $evidenceRoot 'active-blocked-tcp.json'
$deadlineUtc = $null

function Write-QuietShieldRehearsalState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$State,
        [Parameter(Mandatory = $true)]
        [string]$Status
    )
    if ($State -cne $script:stateName) {
        if (@($script:allowedStateTransitions[$script:stateName]) -cnotcontains $State) {
            throw ('Invalid DNS rehearsal state transition: ' + $script:stateName + ' -> ' + $State)
        }
        $script:stateName = $State
    }
    $entry = [ordered]@{
        schemaVersion = 1
        productMarker = 'QuietShield'
        purpose = 'DnsActivationRehearsalState'
        rehearsalId = $script:rehearsalId.ToString('D')
        state = $State
        status = $Status
        timestampUtc = [DateTimeOffset]::UtcNow.ToString('O')
    }
    $entry | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:statePath -Encoding UTF8
    ($entry | ConvertTo-Json -Depth 5 -Compress) | Add-Content -LiteralPath $script:timelinePath -Encoding UTF8
}

function ConvertTo-QuietShieldProcessArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Start-QuietShieldHiddenProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $argumentText = ($Arguments | ForEach-Object { ConvertTo-QuietShieldProcessArgument -Value $_ }) -join ' '
    return Start-Process -FilePath $FilePath -ArgumentList $argumentText -WindowStyle Hidden -PassThru
}

function Wait-QuietShieldFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$Seconds,
        [System.Diagnostics.Process]$Process
    )
    $limit = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    while ([DateTimeOffset]::UtcNow -lt $limit) {
        if (Test-Path -LiteralPath $Path -PathType Leaf) { return $true }
        if ($null -ne $Process -and $Process.HasExited) { return $false }
        Start-Sleep -Milliseconds 250
    }
    return Test-Path -LiteralPath $Path -PathType Leaf
}

function New-QuietShieldRehearsalBackup {
    param(
        [Parameter(Mandatory = $true)][object]$Selected,
        [Parameter(Mandatory = $true)][bool]$Ipv6Enabled
    )
    $adapter = $Selected.Adapter
    $dnsFamilies = @(Get-DnsClientServerAddress -InterfaceIndex ([int]$adapter.InterfaceIndex) -ErrorAction Stop)
    $ipv4 = @($dnsFamilies | Where-Object { [int]$_.AddressFamily -eq 2 })
    $ipv6 = @($dnsFamilies | Where-Object { [int]$_.AddressFamily -eq 23 })
    if ($ipv4.Count -ne 1 -or $ipv6.Count -ne 1) { throw 'The selected adapter DNS families could not be captured exactly.' }
    $document = [ordered]@{
        schemaVersion = 1
        productMarker = 'QuietShield'
        purpose = 'DnsActivationRehearsalBackup'
        backupId = [Guid]::NewGuid().ToString('D')
        rehearsalId = $script:rehearsalId.ToString('D')
        createdAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        adapter = [ordered]@{
            identity = [ordered]@{ interfaceGuid = ([Guid]$adapter.InterfaceGuid).ToString('D'); interfaceIndex = [int]$adapter.InterfaceIndex }
            kind = [string]$Selected.Kind
            families = @(
                [ordered]@{
                    addressFamily = 'IPv4'; enabled = $true
                    automatic = Test-QuietShieldDnsFamilyIsAutomatic -InterfaceGuid ([Guid]$adapter.InterfaceGuid) -AddressFamily 'IPv4'
                    serverAddresses = @($ipv4[0].ServerAddresses | ForEach-Object { [string]$_ })
                },
                [ordered]@{
                    addressFamily = 'IPv6'; enabled = $Ipv6Enabled
                    automatic = Test-QuietShieldDnsFamilyIsAutomatic -InterfaceGuid ([Guid]$adapter.InterfaceGuid) -AddressFamily 'IPv6'
                    serverAddresses = @($ipv6[0].ServerAddresses | ForEach-Object { [string]$_ })
                }
            )
        }
        payloadSha256 = ''
    }
    $document.payloadSha256 = Get-QuietShieldRehearsalBackupPayloadHash -Backup ([pscustomobject]$document)
    [pscustomobject]$document | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:backupPath -Encoding UTF8
    return Test-QuietShieldRehearsalBackup -BackupPath $script:backupPath
}

function Test-QuietShieldResolveDnsNameNxdomainEvidence {
    param([string]$Server = '')
    try {
        if ([string]::IsNullOrWhiteSpace($Server)) {
            [void](Resolve-DnsName 'quietshield-blocked.test' -DnsOnly -NoHostsFile -ErrorAction Stop)
        }
        else {
            [void](Resolve-DnsName 'quietshield-blocked.test' -Server $Server -DnsOnly -NoHostsFile -ErrorAction Stop)
        }
        return $false
    }
    catch {
        return $_.FullyQualifiedErrorId -match 'DNS_ERROR_RCODE_NAME_ERROR'
    }
}

function Test-QuietShieldApprovedAttemptAlreadyRecorded {
    if (-not (Test-Path -LiteralPath $script:attemptRecordsPath -PathType Leaf)) { return $false }
    foreach ($line in @(Get-Content -LiteralPath $script:attemptRecordsPath -ErrorAction Stop)) {
        if ([string]::IsNullOrWhiteSpace([string]$line)) { continue }
        try { $record = [string]$line | ConvertFrom-Json }
        catch { throw ('The append-only rehearsal attempt record is malformed: ' + $_.Exception.Message) }
        if (-not (Test-QuietShieldJsonProperty -Object $record -Name 'attemptId')) { throw 'An append-only rehearsal attempt record has no attemptId.' }
        if ([Guid]$record.attemptId -eq $script:rehearsalId) { return $true }
    }
    return $false
}

function Add-QuietShieldAttemptRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Event,
        [Parameter(Mandatory = $true)][string]$Outcome
    )
    [ordered]@{
        schemaVersion = 1
        productMarker = 'QuietShield'
        purpose = 'DnsActivationRehearsalAttemptRecord'
        attemptId = $script:rehearsalId.ToString('D')
        event = $Event
        outcome = $Outcome
        dnsChangeBegan = $script:dnsChanged
        evidenceRoot = $script:evidenceRoot
        timestampUtc = [DateTimeOffset]::UtcNow.ToString('O')
    } | ConvertTo-Json -Depth 5 -Compress | Add-Content -LiteralPath $script:attemptRecordsPath -Encoding UTF8
}

function Invoke-QuietShieldRawBlockedProbe {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Udp', 'Tcp')][string]$Protocol,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )
    & $script:hostExe --probe --server '127.0.0.1' --port 53 --domain 'quietshield-blocked.test' --protocol $Protocol --expected-rcode 3 --output $OutputPath
    $probeExitCode = $LASTEXITCODE
    if (-not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) { throw ('The raw ' + $Protocol + ' DNS probe produced no evidence file.') }
    $probe = Get-Content -LiteralPath $OutputPath -Raw | ConvertFrom-Json
    if ($probeExitCode -ne 0) { throw ('The raw ' + $Protocol + ' DNS probe returned exit code ' + [string]$probeExitCode + '.') }
    if (-not (Test-QuietShieldRawDnsProbeResult -Result $probe -Protocol $Protocol)) { throw ('The raw ' + $Protocol + ' DNS probe did not pass.') }
    return $probe
}

function Invoke-QuietShieldFallbackRestore {
    param([string]$Reason)
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $script:PSScriptRoot 'Restore-RehearsalDns.ps1') -BackupPath $script:backupPath -ApprovedRollbackFromRehearsal -RollbackReason $Reason
    if ($LASTEXITCODE -ne 0) { throw 'The fallback rehearsal restoration failed. Use the preserved backup and stop for manual recovery.' }
    [ordered]@{ schemaVersion = 1; productMarker = 'QuietShield'; purpose = 'DnsRehearsalRestored'; trigger = $Reason; restoredAtUtc = [DateTimeOffset]::UtcNow.ToString('O') } |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $script:restoredPath -Encoding UTF8
}

function Wait-QuietShieldPort53Released {
    param([int]$Seconds = 15)
    $limit = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    while ([DateTimeOffset]::UtcNow -lt $limit) {
        if ([bool](Test-QuietShieldPort53Availability).Available) { return }
        Start-Sleep -Milliseconds 250
    }
    Assert-QuietShieldPort53Free
}

try {
    $mutexAcquired = $mutex.WaitOne(0, $false)
    if (-not $mutexAcquired) { throw 'Another DNS activation rehearsal is already running.' }
    if (Test-QuietShieldApprovedAttemptAlreadyRecorded) { throw 'This explicitly approved rehearsal attempt was already recorded. Repeated invocation is refused.' }
    [void](New-Item -ItemType Directory -Path $evidenceRoot -Force)
    [void](New-Item -ItemType Directory -Path (Split-Path -Parent $attemptRecordsPath) -Force)
    Add-QuietShieldAttemptRecord -Event 'ApprovedAttemptStarted' -Outcome 'InProgress'
    $attemptStartRecorded = $true
    Write-QuietShieldRehearsalState -State 'Prepared' -Status 'Explicit approval and Administrator context validated; no DNS change yet.'

    $selected = Get-QuietShieldSelectedPhysicalAdapter
    Assert-QuietShieldPort53Free
    $adapterName = [string]$selected.Adapter.Name
    if ([string]::IsNullOrWhiteSpace($adapterName)) { throw 'The selected physical adapter has no usable Name value.' }
    $namedAdapters = @(Get-NetAdapter -Name $adapterName -ErrorAction Stop)
    if ($namedAdapters.Count -ne 1) { throw 'The selected physical adapter Name no longer resolves exactly once.' }
    if ([int]$namedAdapters[0].InterfaceIndex -ne [int]$selected.Adapter.InterfaceIndex) { throw 'The selected physical adapter Name now resolves to a different InterfaceIndex.' }
    $ipv6Binding = @(Get-NetAdapterBinding -Name $adapterName -ComponentID 'ms_tcpip6' -ErrorAction Stop)
    if ($ipv6Binding.Count -ne 1) { throw 'IPv6 binding state is ambiguous.' }
    $ipv6Enabled = [bool]$ipv6Binding[0].Enabled
    $backup = New-QuietShieldRehearsalBackup -Selected $selected -Ipv6Enabled $ipv6Enabled
    $preSnapshot = Get-QuietShieldSafetySnapshot
    $preSnapshot | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $preSnapshotPath -Encoding UTF8

    $hostExe = Join-Path $root 'artifacts\bin\QuietShield.DnsHost\Release\net10.0-windows\QuietShield.DnsHost.exe'
    $watchdogExe = Join-Path $root 'artifacts\bin\QuietShield.DnsWatchdog\Release\net10.0-windows\QuietShield.DnsWatchdog.exe'
    $restoreScript = Join-Path $PSScriptRoot 'Restore-RehearsalDns.ps1'
    foreach ($requiredFile in @($hostExe, $watchdogExe, $restoreScript)) {
        if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) { throw ('Required rehearsal file is missing: ' + $requiredFile) }
    }

    $deadlineUtc = [DateTimeOffset]::UtcNow.AddSeconds($DurationSeconds)

    $watchdogArguments = @(
        '--backup', $backupPath, '--heartbeat', $heartbeatPath, '--host-ready', $hostReadyPath,
        '--armed', $armedPath, '--rollback-request', $rollbackRequestPath, '--restored', $restoredPath,
        '--host-stop', $hostStopPath, '--cancel', $cancelPath, '--restore-script', $restoreScript,
        '--log', $watchdogLogPath, '--orchestrator-pid', [string]$PID, '--deadline-utc', $deadlineUtc.ToString('O')
    )
    $watchdogProcess = Start-QuietShieldHiddenProcess -FilePath $watchdogExe -Arguments $watchdogArguments
    if ($watchdogProcess.HasExited) { throw 'The independent rollback watchdog failed to start.' }
    Write-QuietShieldRehearsalState -State 'WatchdogStarted' -Status 'Independent rollback watchdog started before the resolver.'

    $hostArguments = @(
        '--backup', $backupPath, '--heartbeat', $heartbeatPath, '--ready', $hostReadyPath,
        '--stop', $hostStopPath, '--log', $hostLogPath, '--maximum-runtime-seconds', [string]([Math]::Min(360, $DurationSeconds + 60))
    )
    if ($ipv6Enabled) { $hostArguments += '--enable-ipv6' }
    $hostProcess = Start-QuietShieldHiddenProcess -FilePath $hostExe -Arguments $hostArguments
    if (-not (Wait-QuietShieldFile -Path $hostReadyPath -Seconds 15 -Process $hostProcess)) {
        Set-Content -LiteralPath $cancelPath -Value 'host-startup-failed' -Encoding ASCII
        Set-Content -LiteralPath $hostStopPath -Value 'stop' -Encoding ASCII
        throw 'The temporary DNS host did not become ready. DNS was not changed.'
    }
    $hostReady = Get-Content -LiteralPath $hostReadyPath -Raw | ConvertFrom-Json
    foreach ($property in @('policySnapshotLoaded', 'normalizedBlockedTestDomain', 'udpBlockedRcode', 'tcpBlockedRcode')) {
        if (-not (Test-QuietShieldJsonProperty -Object $hostReady -Name $property)) { throw ('The DNS host readiness evidence is missing: ' + $property) }
    }
    if (-not [bool]$hostReady.policySnapshotLoaded -or [string]$hostReady.normalizedBlockedTestDomain -cne 'quietshield-blocked.test' -or [int]$hostReady.udpBlockedRcode -ne 3 -or [int]$hostReady.tcpBlockedRcode -ne 3) {
        throw 'The DNS host reported ready before its normalized policy and raw UDP/TCP NXDOMAIN checks were complete.'
    }
    Write-QuietShieldRehearsalState -State 'ResolverStarted' -Status 'Temporary IPv4 and applicable IPv6 loopback resolver preflight passed.'

    [void](Resolve-DnsName 'example.com' -Server '127.0.0.1' -DnsOnly -NoHostsFile -ErrorAction Stop)
    $preUdpProbe = Invoke-QuietShieldRawBlockedProbe -Protocol 'Udp' -OutputPath $preUdpProbePath
    $preTcpProbe = Invoke-QuietShieldRawBlockedProbe -Protocol 'Tcp' -OutputPath $preTcpProbePath
    $preResolveDnsNameEvidence = Test-QuietShieldResolveDnsNameNxdomainEvidence -Server '127.0.0.1'

    Set-Content -LiteralPath $armedPath -Value 'rollback-armed-before-dns-change' -Encoding ASCII
    $rollbackArmed = $true
    $dnsObjects = @(Get-DnsClientServerAddress -InterfaceIndex ([int]$selected.Adapter.InterfaceIndex) -ErrorAction Stop)
    $ipv4Object = @($dnsObjects | Where-Object { [int]$_.AddressFamily -eq 2 })
    $ipv6Object = @($dnsObjects | Where-Object { [int]$_.AddressFamily -eq 23 })
    if ($ipv4Object.Count -ne 1 -or ($ipv6Enabled -and $ipv6Object.Count -ne 1)) { throw 'Selected adapter DNS objects changed after backup; rollback was requested.' }
    Set-DnsClientServerAddress -InputObject $ipv4Object[0] -ServerAddresses @('127.0.0.1') -Confirm:$false -ErrorAction Stop
    $dnsChanged = $true
    Write-QuietShieldRehearsalState -State 'DnsChanged' -Status 'The selected adapter entered the temporary loopback DNS change window.'
    if ($ipv6Enabled) { Set-DnsClientServerAddress -InputObject $ipv6Object[0] -ServerAddresses @('::1') -Confirm:$false -ErrorAction Stop }
    Clear-DnsClientCache -ErrorAction Stop

    [void](Resolve-DnsName 'example.com' -DnsOnly -NoHostsFile -ErrorAction Stop)
    $activeUdpProbe = Invoke-QuietShieldRawBlockedProbe -Protocol 'Udp' -OutputPath $activeUdpProbePath
    $activeTcpProbe = Invoke-QuietShieldRawBlockedProbe -Protocol 'Tcp' -OutputPath $activeTcpProbePath
    $activeResolveDnsNameEvidence = Test-QuietShieldResolveDnsNameNxdomainEvidence
    Write-QuietShieldRehearsalState -State 'VerificationPassed' -Status 'Allowed and embedded safe blocked-domain checks passed through system DNS.'
    Write-QuietShieldRehearsalState -State 'RehearsalActive' -Status 'Temporary rehearsal active until the independent watchdog deadline.'

    $waitLimit = $deadlineUtc.AddSeconds(35)
    while ([DateTimeOffset]::UtcNow -lt $waitLimit -and -not (Test-Path -LiteralPath $restoredPath)) {
        if ($watchdogProcess.HasExited) { break }
        Start-Sleep -Milliseconds 500
    }
    if (-not (Test-Path -LiteralPath $restoredPath)) {
        Write-QuietShieldRehearsalState -State 'RollbackStarted' -Status 'Watchdog result was unavailable; invoking the one fallback restoration path.'
        Invoke-QuietShieldFallbackRestore -Reason 'WatchdogUnavailableFallback'
    }
    else {
        Write-QuietShieldRehearsalState -State 'RollbackStarted' -Status 'Independent watchdog initiated restoration at the approved deadline.'
    }
    Write-QuietShieldRehearsalState -State 'DnsRestored' -Status 'Validated original IPv4 and IPv6 DNS state was restored exactly.'
    $restorationVerified = $true

    Set-Content -LiteralPath $hostStopPath -Value 'stop' -Encoding ASCII
    [void](Wait-QuietShieldFile -Path $restoredPath -Seconds 5 -Process $watchdogProcess)
    Wait-QuietShieldPort53Released -Seconds 15
    [void](Resolve-DnsName 'example.com' -DnsOnly -NoHostsFile -ErrorAction Stop)
    $postSnapshot = Get-QuietShieldSafetySnapshot
    $postSnapshot | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $postSnapshotPath -Encoding UTF8
    foreach ($property in @('QuietShieldServiceHash', 'FirewallHash', 'DnsHash', 'AdapterHash', 'StartupHash', 'QuietShieldWfpHash', 'QuietShieldRegistryHash')) {
        if ($preSnapshot.$property -ne $postSnapshot.$property) { throw ('Post-restore system-state comparison failed: ' + $property) }
    }
    Write-QuietShieldRehearsalState -State 'PostRestoreVerified' -Status 'Normal resolution and complete before/after safety snapshots passed.'
    Write-QuietShieldRehearsalState -State 'Completed' -Status 'Temporary rehearsal completed with exact automatic rollback and no permanent activation.'

    $restoredEvidence = Get-Content -LiteralPath $restoredPath -Raw | ConvertFrom-Json
    [ordered]@{
        schemaVersion = 1
        status = 'Passed'
        rehearsalId = $rehearsalId.ToString('D')
        durationSeconds = $DurationSeconds
        adapter = [ordered]@{ interfaceGuid = ([Guid]$selected.Adapter.InterfaceGuid).ToString('D'); interfaceIndex = [int]$selected.Adapter.InterfaceIndex; kind = [string]$selected.Kind }
        originalDns = [ordered]@{
            ipv4Mode = $(if ([bool]$backup.Backup.adapter.families[0].automatic) { 'Automatic' } else { 'Static' })
            ipv4Addresses = '[redacted in summary; retained only in validated backup]'
            ipv6Mode = $(if ([bool]$backup.Backup.adapter.families[1].automatic) { 'Automatic' } else { 'Static' })
            ipv6Addresses = '[redacted in summary; retained only in validated backup]'
        }
        allowedDomain = 'Passed'
        blockedTestDomain = 'NXDOMAIN Passed'
        rawBlockedDomain = [ordered]@{
            preChangeUdpRcode = [int]$preUdpProbe.responseCode
            preChangeTcpRcode = [int]$preTcpProbe.responseCode
            activeUdpRcode = [int]$activeUdpProbe.responseCode
            activeTcpRcode = [int]$activeTcpProbe.responseCode
            preChangeResolveDnsNameSecondaryEvidence = [bool]$preResolveDnsNameEvidence
            activeResolveDnsNameSecondaryEvidence = [bool]$activeResolveDnsNameEvidence
        }
        rollbackReason = [string]$restoredEvidence.trigger
        restorationVerification = 'Passed'
        finalState = $stateName
        backupPath = $backupPath
        timelinePath = $timelinePath
        noPermanentService = $true
        restartRequired = $false
    } | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $resultPath -Encoding UTF8
    Add-QuietShieldAttemptRecord -Event 'ApprovedAttemptFinished' -Outcome 'CompletedActivationRehearsal'
    Write-Output ('DNS activation rehearsal passed and restored original DNS. Evidence: ' + $evidenceRoot)
}
catch {
    $failureMessage = $_.Exception.Message
    if ($rollbackArmed -and -not (Test-Path -LiteralPath $restoredPath)) {
        if ($dnsChanged -and $stateName -ceq 'ResolverStarted') {
            Write-QuietShieldRehearsalState -State 'DnsChanged' -Status 'A partial DNS mutation was detected and requires immediate rollback.'
        }
        if ($stateName -in @('DnsChanged', 'VerificationPassed', 'RehearsalActive')) {
            Write-QuietShieldRehearsalState -State 'RollbackStarted' -Status ('Failure triggered immediate rollback: ' + $failureMessage)
        }
        Set-Content -LiteralPath $rollbackRequestPath -Value 'orchestrator-failure' -Encoding ASCII
        $restored = Wait-QuietShieldFile -Path $restoredPath -Seconds 30 -Process $watchdogProcess
        if (-not $restored) { Invoke-QuietShieldFallbackRestore -Reason 'OrchestratorFailureFallback' }
        $restorationVerified = Test-Path -LiteralPath $restoredPath
    }
    elseif (-not $rollbackArmed) {
        if (Test-Path -LiteralPath $evidenceRoot) { Set-Content -LiteralPath $cancelPath -Value 'cancel-before-dns-change' -Encoding ASCII }
    }
    if (Test-Path -LiteralPath $evidenceRoot) {
        [ordered]@{ schemaVersion = 1; status = 'Failed'; state = $stateName; error = $failureMessage; dnsChanged = $dnsChanged; restorationVerified = $restorationVerified; evidenceRoot = $evidenceRoot } |
            ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $resultPath -Encoding UTF8
    }
    if ($attemptStartRecorded) {
        $attemptOutcome = if (-not $dnsChanged) { 'FailedBeforeDnsChange' } elseif ($restorationVerified) { 'FailedAfterDnsChangeRestored' } else { 'FailedAfterDnsChangeRestorationUnverified' }
        try { Add-QuietShieldAttemptRecord -Event 'ApprovedAttemptFinished' -Outcome $attemptOutcome }
        catch { $failureMessage = $failureMessage + ' Attempt-record append also failed: ' + $_.Exception.Message }
    }
    throw
}
finally {
    if (Test-Path -LiteralPath $evidenceRoot) { Set-Content -LiteralPath $hostStopPath -Value 'stop' -Encoding ASCII }
    if ($mutexAcquired) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
