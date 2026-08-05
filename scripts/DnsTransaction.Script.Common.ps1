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

        $addressSet = @{}
        foreach ($server in @($adapter.serverAddresses)) {
            $parsedAddress = $null
            if (-not [System.Net.IPAddress]::TryParse([string]$server, [ref]$parsedAddress)) {
                throw 'The DNS backup contains a non-IP DNS server value.'
            }
            if ($addressSet.ContainsKey([string]$server)) {
                throw 'The DNS backup contains a duplicate DNS server value.'
            }
            $addressSet[[string]$server] = $true
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
