Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Test-QuietShieldJsonProperty {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return $null -ne $Object.PSObject.Properties[$Name]
}

function Get-QuietShieldDnsBackupPayloadHash {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Backup
    )

    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $created = ([DateTimeOffset]::Parse([string]$Backup.createdAtUtc, $invariant)).ToUniversalTime().ToString('O', $invariant)
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append([int]$Backup.schemaVersion).Append('|')
    [void]$builder.Append([string]$Backup.productMarker).Append('|')
    [void]$builder.Append([string]$Backup.purpose).Append('|')
    [void]$builder.Append(([Guid]$Backup.backupId).ToString('D')).Append('|')
    [void]$builder.Append($created).Append("`n")

    $adapters = @($Backup.adapters | Sort-Object @{ Expression = { ([Guid]$_.identity.interfaceGuid).ToString('D') } }, @{ Expression = { [int]$_.identity.interfaceIndex } })
    foreach ($adapter in $adapters) {
        [void]$builder.Append(([Guid]$adapter.identity.interfaceGuid).ToString('D')).Append('|')
        [void]$builder.Append([int]$adapter.identity.interfaceIndex).Append('|')
        if ([bool]$adapter.automatic) {
            [void]$builder.Append('Automatic')
        }
        else {
            [void]$builder.Append('Static')
        }
        [void]$builder.Append('|')
        [void]$builder.Append((@($adapter.serverAddresses) -join ',')).Append("`n")
    }

    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($builder.ToString())
        return ([System.BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '')
    }
    finally {
        $algorithm.Dispose()
    }
}

function Test-QuietShieldDnsBackup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )

    $resolved = [System.IO.Path]::GetFullPath($BackupPath)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw ('The specified QuietShield DNS backup does not exist: ' + $resolved)
    }

    try {
        $backup = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
    }
    catch {
        throw ('The DNS backup JSON is malformed: ' + $_.Exception.Message)
    }

    foreach ($property in @('schemaVersion', 'productMarker', 'purpose', 'backupId', 'createdAtUtc', 'adapters', 'payloadSha256')) {
        if (-not (Test-QuietShieldJsonProperty -Object $backup -Name $property)) {
            throw ('The DNS backup is missing required property: ' + $property)
        }
    }
    if ([int]$backup.schemaVersion -ne 1 -or [string]$backup.productMarker -cne 'QuietShield' -or [string]$backup.purpose -cne 'OriginalDnsBackup') {
        throw 'The file is not a supported QuietShield original-DNS backup.'
    }
    if ([Guid]$backup.backupId -eq [Guid]::Empty) {
        throw 'The DNS backup identifier is invalid.'
    }
    [void][DateTimeOffset]::Parse([string]$backup.createdAtUtc, [System.Globalization.CultureInfo]::InvariantCulture)
    if (@($backup.adapters).Count -eq 0) {
        throw 'The DNS backup contains no adapters.'
    }

    $identities = @{}
    foreach ($adapter in @($backup.adapters)) {
        if (-not (Test-QuietShieldJsonProperty -Object $adapter -Name 'identity') -or
            -not (Test-QuietShieldJsonProperty -Object $adapter -Name 'automatic') -or
            -not (Test-QuietShieldJsonProperty -Object $adapter -Name 'serverAddresses')) {
            throw 'The DNS backup contains a malformed adapter entry.'
        }
        $interfaceGuid = [Guid]$adapter.identity.interfaceGuid
        $interfaceIndex = [int]$adapter.identity.interfaceIndex
        if ($interfaceGuid -eq [Guid]::Empty -or $interfaceIndex -le 0) {
            throw 'The DNS backup contains an invalid adapter identity.'
        }
        $identityKey = $interfaceGuid.ToString('D') + '|' + $interfaceIndex
        if ($identities.ContainsKey($identityKey)) {
            throw 'The DNS backup contains a duplicate adapter identity.'
        }
        $identities[$identityKey] = $true

        foreach ($server in @($adapter.serverAddresses)) {
            $parsedAddress = $null
            if (-not [System.Net.IPAddress]::TryParse([string]$server, [ref]$parsedAddress)) {
                throw 'The DNS backup contains a non-IP DNS server value.'
            }
        }
        if (-not [bool]$adapter.automatic -and @($adapter.serverAddresses).Count -eq 0) {
            throw 'A static DNS backup entry is missing its original DNS server values.'
        }
    }

    if ([string]$backup.payloadSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
        throw 'The DNS backup hash format is invalid.'
    }
    $computed = Get-QuietShieldDnsBackupPayloadHash -Backup $backup
    if ($computed -cne ([string]$backup.payloadSha256).ToUpperInvariant()) {
        throw 'The DNS backup payload hash is invalid.'
    }

    return [pscustomobject]@{
        Path = $resolved
        Backup = $backup
        Status = 'Validated QuietShield original-DNS backup'
    }
}

function Test-QuietShieldDnsAdapterIdentities {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Backup
    )

    $currentAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    $matches = @()
    foreach ($saved in @($Backup.adapters)) {
        $savedGuid = [Guid]$saved.identity.interfaceGuid
        $savedIndex = [int]$saved.identity.interfaceIndex
        $match = @($currentAdapters | Where-Object {
            [Guid]$_.InterfaceGuid -eq $savedGuid -and [int]$_.InterfaceIndex -eq $savedIndex
        })
        if ($match.Count -ne 1) {
            throw ("The validated backup adapter identity no longer matches exactly: {0}|{1}" -f $savedGuid.ToString('D'), $savedIndex)
        }
        $matches += $match[0]
    }
    return $matches
}

function Get-QuietShieldRehearsalBackupPayloadHash {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Backup
    )

    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $created = ([DateTimeOffset]::Parse([string]$Backup.createdAtUtc, $invariant)).ToUniversalTime().ToString('O', $invariant)
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append([int]$Backup.schemaVersion).Append('|')
    [void]$builder.Append([string]$Backup.productMarker).Append('|')
    [void]$builder.Append([string]$Backup.purpose).Append('|')
    [void]$builder.Append(([Guid]$Backup.backupId).ToString('D')).Append('|')
    [void]$builder.Append(([Guid]$Backup.rehearsalId).ToString('D')).Append('|')
    [void]$builder.Append($created).Append("`n")
    [void]$builder.Append(([Guid]$Backup.adapter.identity.interfaceGuid).ToString('D')).Append('|')
    [void]$builder.Append([int]$Backup.adapter.identity.interfaceIndex).Append('|')
    [void]$builder.Append([string]$Backup.adapter.kind).Append("`n")
    $families = @($Backup.adapter.families | Sort-Object @{ Expression = { if ([string]$_.addressFamily -ceq 'IPv4') { 0 } else { 1 } } })
    foreach ($family in $families) {
        [void]$builder.Append([string]$family.addressFamily).Append('|')
        if ([bool]$family.enabled) { [void]$builder.Append('Enabled') } else { [void]$builder.Append('Disabled') }
        [void]$builder.Append('|')
        if ([bool]$family.automatic) { [void]$builder.Append('Automatic') } else { [void]$builder.Append('Static') }
        [void]$builder.Append('|')
        [void]$builder.Append((@($family.serverAddresses) -join ',')).Append("`n")
    }
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($builder.ToString())
        return ([System.BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '')
    }
    finally {
        $algorithm.Dispose()
    }
}

function Test-QuietShieldRehearsalBackup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )

    $resolved = [System.IO.Path]::GetFullPath($BackupPath)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw ('The rehearsal backup does not exist: ' + $resolved)
    }
    try { $backup = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json }
    catch { throw ('The rehearsal backup JSON is malformed: ' + $_.Exception.Message) }
    foreach ($property in @('schemaVersion', 'productMarker', 'purpose', 'backupId', 'rehearsalId', 'createdAtUtc', 'adapter', 'payloadSha256')) {
        if (-not (Test-QuietShieldJsonProperty -Object $backup -Name $property)) {
            throw ('The rehearsal backup is missing required property: ' + $property)
        }
    }
    if ([int]$backup.schemaVersion -ne 1 -or [string]$backup.productMarker -cne 'QuietShield' -or [string]$backup.purpose -cne 'DnsActivationRehearsalBackup') {
        throw 'The file is not a supported QuietShield DNS activation rehearsal backup.'
    }
    if ([Guid]$backup.backupId -eq [Guid]::Empty -or [Guid]$backup.rehearsalId -eq [Guid]::Empty) {
        throw 'The rehearsal backup identity is invalid.'
    }
    [void][DateTimeOffset]::Parse([string]$backup.createdAtUtc, [System.Globalization.CultureInfo]::InvariantCulture)
    $adapterGuid = [Guid]$backup.adapter.identity.interfaceGuid
    $adapterIndex = [int]$backup.adapter.identity.interfaceIndex
    if ($adapterGuid -eq [Guid]::Empty -or $adapterIndex -le 0 -or @('Ethernet', 'WiFi') -notcontains [string]$backup.adapter.kind) {
        throw 'The rehearsal backup adapter identity or type is invalid.'
    }
    $families = @($backup.adapter.families)
    if ($families.Count -ne 2 -or @($families | Where-Object { [string]$_.addressFamily -ceq 'IPv4' }).Count -ne 1 -or @($families | Where-Object { [string]$_.addressFamily -ceq 'IPv6' }).Count -ne 1) {
        throw 'The rehearsal backup must contain exactly one IPv4 and one IPv6 state.'
    }
    foreach ($family in $families) {
        $familyName = [string]$family.addressFamily
        foreach ($server in @($family.serverAddresses)) {
            $address = $null
            if (-not [System.Net.IPAddress]::TryParse([string]$server, [ref]$address)) { throw 'The rehearsal backup contains a non-IP DNS value.' }
            if ($familyName -ceq 'IPv4' -and $address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { throw 'The IPv4 backup contains a non-IPv4 value.' }
            if ($familyName -ceq 'IPv6' -and $address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) { throw 'The IPv6 backup contains a non-IPv6 value.' }
        }
        if ([bool]$family.enabled -and -not [bool]$family.automatic -and @($family.serverAddresses).Count -eq 0) {
            throw 'An enabled static DNS family has no original server values.'
        }
    }
    if ([string]$backup.payloadSha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw 'The rehearsal backup hash format is invalid.' }
    $computed = Get-QuietShieldRehearsalBackupPayloadHash -Backup $backup
    if ($computed -cne ([string]$backup.payloadSha256).ToUpperInvariant()) { throw 'The rehearsal backup payload hash is invalid.' }
    return [pscustomobject]@{ Path = $resolved; Backup = $backup; Status = 'Validated QuietShield rehearsal backup' }
}

function Test-QuietShieldAdapterIsExactRehearsalMatch {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Backup
    )

    $guid = [Guid]$Backup.adapter.identity.interfaceGuid
    $index = [int]$Backup.adapter.identity.interfaceIndex
    $matches = @(Get-NetAdapter -Physical -IncludeHidden -ErrorAction Stop | Where-Object {
        [Guid]$_.InterfaceGuid -eq $guid -and [int]$_.InterfaceIndex -eq $index
    })
    if ($matches.Count -ne 1) { throw 'The rehearsal backup adapter no longer matches exactly.' }
    return $matches[0]
}

function Test-QuietShieldDnsFamilyIsAutomatic {
    param(
        [Parameter(Mandatory = $true)]
        [Guid]$InterfaceGuid,
        [Parameter(Mandatory = $true)]
        [ValidateSet('IPv4', 'IPv6')]
        [string]$AddressFamily
    )

    $service = if ($AddressFamily -ceq 'IPv4') { 'Tcpip' } else { 'Tcpip6' }
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $service + '\Parameters\Interfaces\{' + $InterfaceGuid.ToString('D') + '}'
    if (-not (Test-Path -LiteralPath $path)) { return $true }
    $properties = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
    $nameServer = $properties.PSObject.Properties['NameServer']
    return $null -eq $nameServer -or [string]::IsNullOrWhiteSpace([string]$nameServer.Value)
}

function Test-QuietShieldStringArrayExact {
    param(
        [string[]]$Expected,
        [string[]]$Actual
    )

    if (@($Expected).Count -ne @($Actual).Count) { return $false }
    for ($index = 0; $index -lt @($Expected).Count; $index++) {
        if (-not [string]::Equals([string]$Expected[$index], [string]$Actual[$index], [StringComparison]::OrdinalIgnoreCase)) { return $false }
    }
    return $true
}

function Test-QuietShieldPort53Availability {
    $conflictingUdp = @(Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue)
    $conflictingTcp = @(Get-NetTCPConnection -LocalPort 53 -State Listen -ErrorAction SilentlyContinue)
    return [pscustomobject]@{
        Available = ($conflictingUdp.Count -eq 0 -and $conflictingTcp.Count -eq 0)
        UdpConflictCount = $conflictingUdp.Count
        TcpConflictCount = $conflictingTcp.Count
    }
}

function Assert-QuietShieldPort53Free {
    $availability = Test-QuietShieldPort53Availability
    if (-not [bool]$availability.Available) {
        throw 'Loopback port 53 is already in use; the rehearsal stops without changing DNS.'
    }
}

function Get-QuietShieldSelectedPhysicalAdapter {
    $eligible = @()
    foreach ($adapter in @(Get-NetAdapter -Physical -ErrorAction Stop)) {
        $kind = if ([string]$adapter.PhysicalMediaType -ceq 'Native 802.11' -and [int]$adapter.InterfaceType -eq 71) {
            'WiFi'
        }
        elseif ([string]$adapter.PhysicalMediaType -ceq '802.3' -and [int]$adapter.InterfaceType -eq 6) {
            'Ethernet'
        }
        else {
            'Other'
        }
        if ([string]$adapter.Status -ceq 'Up' -and [bool]$adapter.HardwareInterface -and -not [bool]$adapter.Virtual -and @('WiFi', 'Ethernet') -contains $kind) {
            $eligible += [pscustomobject]@{ Adapter = $adapter; Kind = $kind }
        }
    }
    if ($eligible.Count -eq 0) { throw 'No active supported physical Wi-Fi or Ethernet adapter is available. VPN-only, virtual-only, disconnected, and unsupported adapters are refused.' }
    if ($eligible.Count -ne 1) { throw 'Physical-adapter selection is ambiguous. Exactly one active Wi-Fi or Ethernet adapter is required.' }
    return $eligible[0]
}

function Test-QuietShieldRawDnsProbeResult {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Result,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Udp', 'Tcp')]
        [string]$Protocol,
        [string]$ExpectedDomain = 'quietshield-blocked.test'
    )

    foreach ($property in @('protocol', 'queriedName', 'responseQuestionName', 'expectedTransactionId', 'responseTransactionId', 'isResponse', 'responseCode', 'validationSucceeded', 'passed')) {
        if (-not (Test-QuietShieldJsonProperty -Object $Result -Name $property)) {
            throw ('The raw DNS probe result is missing required property: ' + $property)
        }
    }
    if ([string]$Result.protocol -cne $Protocol) { throw 'The raw DNS probe protocol does not match the requested protocol.' }
    if ([string]$Result.queriedName -cne $ExpectedDomain -or [string]$Result.responseQuestionName -cne $ExpectedDomain) {
        throw 'The raw DNS response did not echo the exact embedded test-domain question.'
    }
    if ([int]$Result.expectedTransactionId -le 0 -or [int]$Result.expectedTransactionId -ne [int]$Result.responseTransactionId) {
        throw 'The raw DNS response transaction ID does not match the query.'
    }
    if (-not [bool]$Result.isResponse -or -not [bool]$Result.validationSucceeded) {
        throw 'The raw DNS packet is not a valid matching response.'
    }
    if ([int]$Result.responseCode -ne 3) { throw ('The raw DNS response RCODE is not NXDOMAIN (3); actual: ' + [string]$Result.responseCode) }
    if (-not [bool]$Result.passed) { throw 'The raw DNS probe did not pass all deterministic checks.' }
    return $true
}
