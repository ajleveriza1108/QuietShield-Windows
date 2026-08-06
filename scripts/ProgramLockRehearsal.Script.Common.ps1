Set-StrictMode -Version 2.0

function ConvertTo-QuietShieldUtcDateTimeOffset {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Value)

    if ($Value -is [DateTimeOffset]) {
        return ([DateTimeOffset]$Value).ToUniversalTime()
    }

    if ($Value -is [DateTime]) {
        $dateTime = [DateTime]$Value
        if ($dateTime.Kind -eq [DateTimeKind]::Unspecified) {
            $dateTime = [DateTime]::SpecifyKind($dateTime, [DateTimeKind]::Utc)
        }
        return ([DateTimeOffset]$dateTime).ToUniversalTime()
    }

    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse(
        [string]$Value,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$parsed)) {
        throw 'The watchdog time value is not a valid round-trip DateTimeOffset.'
    }
    return $parsed.ToUniversalTime()
}

function Get-QuietShieldProgramLockWatchdogTrigger {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][bool]$RuleCreated,
        [Parameter(Mandatory = $true)][bool]$ParentAlive,
        [Parameter(Mandatory = $true)]$CurrentTime,
        [Parameter(Mandatory = $true)]$Deadline,
        [Parameter(Mandatory = $true)][bool]$RollbackRequested,
        [Parameter(Mandatory = $true)][bool]$VerificationFailed,
        [Parameter(Mandatory = $true)][bool]$ProbeFailed,
        [Parameter(Mandatory = $true)][bool]$HeartbeatExists,
        $HeartbeatLastWriteTime = $null,
        [ValidateRange(1, 120)][int]$HeartbeatTimeoutSeconds = 8
    )

    if (-not $RuleCreated) { return $null }
    if ($RollbackRequested) { return 'RollbackRequested' }
    if ($VerificationFailed) { return 'VerificationFailed' }
    if ($ProbeFailed) { return 'ProbeExitedUnexpectedly' }

    $currentUtc = ConvertTo-QuietShieldUtcDateTimeOffset -Value $CurrentTime
    $deadlineUtc = ConvertTo-QuietShieldUtcDateTimeOffset -Value $Deadline
    if ($currentUtc -ge $deadlineUtc) { return 'DeadlineExpired' }
    if (-not $ParentAlive) { return 'ParentProcessLost' }
    if ($HeartbeatExists) {
        if ($null -eq $HeartbeatLastWriteTime) { throw 'The watchdog heartbeat timestamp is required when the heartbeat exists.' }
        $heartbeatUtc = ConvertTo-QuietShieldUtcDateTimeOffset -Value $HeartbeatLastWriteTime
        if (($currentUtc - $heartbeatUtc).TotalSeconds -gt $HeartbeatTimeoutSeconds) { return 'HeartbeatLost' }
    }
    return $null
}

function New-QuietShieldProgramLockRehearsalDescription {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][Guid]$TransactionId)

    if ($TransactionId -eq [Guid]::Empty) { throw 'A Program Lock rehearsal transaction ID is required.' }
    $description = 'QuietShield rehearsal; schema=1; tx=' + $TransactionId.ToString('N') + '; temporary=1'
    [void](Test-QuietShieldProgramLockRehearsalDescription -Description $description -TransactionId $TransactionId)
    return $description
}

function Test-QuietShieldProgramLockRehearsalDescription {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Description,
        [Parameter(Mandatory = $true)][Guid]$TransactionId
    )

    if ([string]::IsNullOrEmpty($Description)) { throw 'The Firewall description is required.' }
    if ($Description.Length -gt 160) { throw 'The Firewall description exceeds 160 characters.' }
    foreach ($character in $Description.ToCharArray()) {
        $codePoint = [int]$character
        if ($codePoint -lt 32 -or $codePoint -gt 126) { throw 'The Firewall description must contain printable ASCII characters only.' }
    }
    $expected = 'QuietShield rehearsal; schema=1; tx=' + $TransactionId.ToString('N') + '; temporary=1'
    if ($Description -cne $expected) { throw 'The Firewall description does not match the deterministic transaction format.' }
    return $true
}

function Get-QuietShieldProgramLockRehearsalHash {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$State)

    $builder = New-Object Text.StringBuilder
    [void]$builder.Append([int]$State.schemaVersion).Append('|').Append([string]$State.productMarker).Append('|').Append([string]$State.purpose).Append('|')
    [void]$builder.Append(([Guid]$State.transactionId).ToString('D')).Append('|').Append(([DateTimeOffset]$State.createdAtUtc).ToUniversalTime().ToString('O')).Append('|')
    [void]$builder.Append(([DateTimeOffset]$State.expiresAtUtc).ToUniversalTime().ToString('O')).Append('|').Append([int]$State.durationSeconds).Append('|')
    [void]$builder.Append([string]$State.state).Append('|').Append([bool]$State.completed).Append('|').Append([bool]$State.firewallServiceHealthy).Append('|')
    [void]$builder.Append([bool]$State.baseFilteringEngineHealthy).Append("`n")
    $rule = $State.rule
    [void]$builder.Append('R|').Append([string]$rule.ownershipMarker).Append('|').Append([int]$rule.schemaVersion).Append('|').Append([string]$rule.name).Append('|')
    [void]$builder.Append([string]$rule.description).Append('|').Append([string]$rule.programPath).Append('|').Append([string]$rule.direction).Append('|')
    [void]$builder.Append([string]$rule.action).Append('|').Append([bool]$rule.enabled).Append('|').Append([string]$rule.profile).Append('|')
    [void]$builder.Append([string]$rule.protocol).Append('|').Append([string]$rule.remoteAddress).Append('|').Append([int]$rule.remotePort).Append('|')
    [void]$builder.Append([string]$rule.localAddress).Append('|').Append([string]$rule.localPort).Append('|').Append([string]$rule.edgeTraversal).Append("`n")
    foreach ($name in @($State.existingOwnedRehearsalRuleNames)) { [void]$builder.Append('E|').Append([string]$name).Append("`n") }
    foreach ($profile in @($State.firewallProfiles)) {
        [void]$builder.Append('F|').Append([string]$profile.name).Append('|').Append([bool]$profile.enabled).Append('|')
        [void]$builder.Append([string]$profile.defaultInboundAction).Append('|').Append([string]$profile.defaultOutboundAction).Append("`n")
    }
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($builder.ToString())))).Replace('-', '') }
    finally { $algorithm.Dispose() }
}

function Set-QuietShieldProgramLockRehearsalState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$StatePath,
        [Parameter(Mandatory = $true)][string]$NewState,
        [bool]$Completed = $false
    )

    $State.state = $NewState
    $State.completed = $Completed
    $State.payloadSha256 = Get-QuietShieldProgramLockRehearsalHash -State $State
    $resolved = [IO.Path]::GetFullPath($StatePath)
    $directory = Split-Path -Parent $resolved
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { [void](New-Item -ItemType Directory -Path $directory -Force) }
    $temporary = $resolved + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $State | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $temporary -Encoding UTF8
        Move-Item -LiteralPath $temporary -Destination $resolved -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) { Remove-Item -LiteralPath $temporary -Force }
    }
    return $State
}

function Test-QuietShieldProgramLockRehearsalState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$StatePath,
        [switch]$AllowCompleted
    )

    $resolved = [IO.Path]::GetFullPath($StatePath)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw ('Program Lock rehearsal state was not found: ' + $resolved) }
    try { $state = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json }
    catch { throw ('Program Lock rehearsal state JSON is malformed: ' + $_.Exception.Message) }
    if ([int]$state.schemaVersion -ne 1 -or [string]$state.productMarker -cne 'QuietShield' -or [string]$state.purpose -cne 'ProgramLockFirewallRehearsal') {
        throw 'Program Lock rehearsal state schema, ownership, or purpose is foreign.'
    }
    $transactionId = [Guid]$state.transactionId
    if ($transactionId -eq [Guid]::Empty) { throw 'Program Lock rehearsal transaction ID is invalid.' }
    $duration = [int]$state.durationSeconds
    if ($duration -lt 1 -or $duration -gt 120) { throw 'Program Lock rehearsal duration exceeds the 120-second maximum.' }
    if (-not $AllowCompleted -and ([bool]$state.completed -or [string]$state.state -ceq 'Completed')) { throw 'Completed Program Lock rehearsal state is refused.' }
    $rule = $state.rule
    $expectedName = 'QuietShield.ProgramLock.Rehearsal.' + $transactionId.ToString('D')
    if ([string]$rule.ownershipMarker -cne 'QuietShield' -or [int]$rule.schemaVersion -ne 1 -or [string]$rule.name -cne $expectedName) {
        throw 'Program Lock rehearsal rule identity is foreign or ambiguous.'
    }
    if ([IO.Path]::GetFileName([string]$rule.programPath) -ine 'QuietShield.ConnectionProbe.exe' -or -not [IO.Path]::IsPathRooted([string]$rule.programPath)) {
        throw 'Program Lock rehearsal state does not target the exact dedicated probe executable.'
    }
    $parsedAddress = $null
    if (-not [Net.IPAddress]::TryParse([string]$rule.remoteAddress, [ref]$parsedAddress) -or [int]$rule.remotePort -ne 443) {
        throw 'Program Lock rehearsal endpoint is invalid.'
    }
    $expectedValues = [ordered]@{ direction = 'Outbound'; action = 'Block'; profile = 'Any'; protocol = 'TCP'; localAddress = 'Any'; localPort = 'Any'; edgeTraversal = 'Block' }
    foreach ($property in $expectedValues.Keys) {
        if ([string]$rule.$property -cne [string]$expectedValues[$property]) { throw ('Program Lock rehearsal rule property is invalid: ' + $property) }
    }
    if (-not [bool]$rule.enabled) { throw 'Program Lock rehearsal rule must be enabled.' }
    [void](Test-QuietShieldProgramLockRehearsalDescription -Description ([string]$rule.description) -TransactionId $transactionId)
    $expectedHash = Get-QuietShieldProgramLockRehearsalHash -State $state
    if ([string]$state.payloadSha256 -cne $expectedHash) { throw 'Program Lock rehearsal SHA-256 payload verification failed.' }
    return [pscustomobject]@{ State = $state; Path = $resolved; PayloadSha256 = $expectedHash }
}

function Get-QuietShieldExactProgramLockRehearsalRule {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$RuleName)

    if ($RuleName -cnotmatch '^QuietShield\.ProgramLock\.Rehearsal\.[0-9a-fA-F-]{36}$') { throw 'Exact rehearsal rule name validation failed.' }
    $rules = @(Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue)
    if ($rules.Count -gt 1) { throw 'The exact rehearsal rule identity is ambiguous.' }
    if ($rules.Count -eq 0) { return $null }
    return $rules[0]
}

function Test-QuietShieldExactProgramLockRehearsalRuleProperties {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)]$Rule
    )

    if ([string]$Rule.Name -cne [string]$State.rule.name -or [string]$Rule.DisplayName -cne [string]$State.rule.name -or
        [string]$Rule.Description -cne [string]$State.rule.description -or [string]$Rule.Direction -cne 'Outbound' -or
        [string]$Rule.Action -cne 'Block' -or [string]$Rule.Enabled -cne 'True' -or [string]$Rule.Profile -cne 'Any' -or
        [string]$Rule.EdgeTraversalPolicy -cne 'Block') { throw 'The exact rehearsal rule base properties do not match the transaction.' }
    $application = @($Rule | Get-NetFirewallApplicationFilter)
    $address = @($Rule | Get-NetFirewallAddressFilter)
    $port = @($Rule | Get-NetFirewallPortFilter)
    if ($application.Count -ne 1 -or [IO.Path]::GetFullPath([string]$application[0].Program) -ine [IO.Path]::GetFullPath([string]$State.rule.programPath)) {
        throw 'The exact rehearsal application filter does not match.'
    }
    if ($address.Count -ne 1 -or [string]$address[0].RemoteAddress -cne [string]$State.rule.remoteAddress -or [string]$address[0].LocalAddress -cne 'Any') {
        throw 'The exact rehearsal address filter does not match.'
    }
    if ($port.Count -ne 1 -or [string]$port[0].Protocol -notin @('6', 'TCP') -or [string]$port[0].RemotePort -cne '443' -or [string]$port[0].LocalPort -cne 'Any') {
        throw 'The exact rehearsal port filter does not match.'
    }
    return $true
}

function Add-QuietShieldProgramLockRehearsalEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$EvidencePath,
        [Parameter(Mandatory = $true)]$Entry
    )

    $directory = Split-Path -Parent ([IO.Path]::GetFullPath($EvidencePath))
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { [void](New-Item -ItemType Directory -Path $directory -Force) }
    ($Entry | ConvertTo-Json -Depth 8 -Compress) + [Environment]::NewLine | Add-Content -LiteralPath $EvidencePath -Encoding UTF8
}

function Test-QuietShieldProgramLockWatchdogCompletionEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$EvidencePath,
        [Parameter(Mandatory = $true)][Guid]$TransactionId,
        [Parameter(Mandatory = $true)][string]$RuleName
    )

    if (-not (Test-Path -LiteralPath $EvidencePath -PathType Leaf)) { throw 'The append-only watchdog evidence file was not found.' }
    $transactionText = $TransactionId.ToString('D')
    $records = @()
    $recordIndex = 0
    foreach ($line in Get-Content -LiteralPath $EvidencePath) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $recordIndex++
        try { $entry = $line | ConvertFrom-Json }
        catch { throw ('The append-only watchdog evidence contains malformed JSON at record ' + [string]$recordIndex + '.') }
        if ($null -eq $entry.PSObject.Properties['transactionId'] -or [string]$entry.transactionId -cne $transactionText) { continue }
        if ([int]$entry.schemaVersion -ne 1 -or [string]$entry.productMarker -cne 'QuietShield' -or [string]$entry.purpose -cne 'ProgramLockFirewallRehearsalEvidence') {
            throw 'The watchdog completion evidence has foreign ownership, purpose, or schema.'
        }
        $records += [pscustomobject]@{ Index = $recordIndex; Entry = $entry }
    }

    $deadline = @($records | Where-Object {
        [string]$_.Entry.event -ceq 'WatchdogRollbackTriggered' -and $null -ne $_.Entry.PSObject.Properties['trigger'] -and [string]$_.Entry.trigger -ceq 'DeadlineExpired'
    })
    $removed = @($records | Where-Object {
        [string]$_.Entry.event -ceq 'ExactRuleRemoved' -and $null -ne $_.Entry.PSObject.Properties['ruleName'] -and [string]$_.Entry.ruleName -ceq $RuleName
    })
    $stopped = @($records | Where-Object { [string]$_.Entry.event -ceq 'WatchdogStoppedAfterVerifiedCleanup' })
    if ($deadline.Count -ne 1) { throw 'Exactly one watchdog deadline trigger is required.' }
    if ($removed.Count -lt 1) { throw 'Watchdog completion evidence does not contain exact recorded-rule removal.' }
    if ($stopped.Count -ne 1) { throw 'Exactly one verified watchdog-stop event is required.' }
    if ($deadline[0].Index -ge $removed[0].Index -or $removed[0].Index -ge $stopped[0].Index) {
        throw 'Watchdog cleanup evidence is out of order.'
    }

    return [pscustomobject][ordered]@{
        Valid = $true
        DeadlineTriggerCount = $deadline.Count
        ExactRuleRemovalCount = $removed.Count
        VerifiedStopCount = $stopped.Count
    }
}
