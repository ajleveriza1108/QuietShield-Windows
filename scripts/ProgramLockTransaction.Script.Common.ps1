Set-StrictMode -Version 2.0

function Get-QuietShieldProgramLockSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Value)

    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace('-', '')
    }
    finally {
        $algorithm.Dispose()
    }
}

function Get-QuietShieldProgramLockBackupPayloadHash {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Backup)

    $created = [DateTimeOffset]::Parse([string]$Backup.createdAtUtc, [Globalization.CultureInfo]::InvariantCulture)
    $builder = New-Object Text.StringBuilder
    [void]$builder.Append([int]$Backup.schemaVersion).Append('|').Append([string]$Backup.productMarker).Append('|').Append([string]$Backup.purpose).Append('|')
    [void]$builder.Append(([Guid]$Backup.backupId).ToString('D')).Append('|').Append(([Guid]$Backup.transactionId).ToString('D')).Append('|')
    [void]$builder.Append($created.ToUniversalTime().ToString('O')).Append('|').Append([string]$Backup.activeProfileId).Append("`n")

    foreach ($policy in @($Backup.programPolicies)) {
        [void]$builder.Append('P|').Append([string]$policy.stableApplicationIdentity).Append('|').Append([string]$policy.policy).Append("`n")
    }
    foreach ($identity in @($Backup.applicationIdentities)) {
        [void]$builder.Append('I|').Append([string]$identity.stableApplicationIdentity).Append('|').Append([string]$identity.kind).Append('|')
        [void]$builder.Append([string]$identity.executablePath).Append('|').Append([string]$identity.msixPackageIdentity).Append('|')
        [void]$builder.Append([string]$identity.pathStatus).Append('|').Append([bool]$identity.isSystemComponent).Append("`n")
    }
    foreach ($entry in @($Backup.quietShieldOwnedRules)) {
        [void]$builder.Append('R|').Append([int]$entry.originalOrder).Append('|').Append([string]$entry.rulePayloadSha256).Append("`n")
    }
    return Get-QuietShieldProgramLockSha256 -Value $builder.ToString()
}

function Test-QuietShieldProgramLockBackup {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$BackupPath)

    $resolved = [IO.Path]::GetFullPath($BackupPath)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw ('Program Lock backup was not found: ' + $resolved)
    }
    try {
        $backup = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
    }
    catch {
        throw ('Program Lock backup JSON is malformed: ' + $_.Exception.Message)
    }
    if ([int]$backup.schemaVersion -ne 1) { throw 'Program Lock backup schema is unsupported.' }
    if ([string]$backup.productMarker -cne 'QuietShield' -or [string]$backup.purpose -cne 'ProgramLockTransactionBackup') {
        throw 'Program Lock backup ownership or purpose is foreign.'
    }
    if ([Guid]$backup.backupId -eq [Guid]::Empty -or [Guid]$backup.transactionId -eq [Guid]::Empty) {
        throw 'Program Lock backup identity is invalid.'
    }
    if ([string]::IsNullOrWhiteSpace([string]$backup.activeProfileId)) { throw 'Program Lock backup profile is missing.' }
    if (@($backup.programPolicies).Count -ne @($backup.applicationIdentities).Count) {
        throw 'Program Lock backup policy and identity counts differ.'
    }
    $expectedHash = Get-QuietShieldProgramLockBackupPayloadHash -Backup $backup
    if ([string]$backup.payloadSha256 -cne $expectedHash) { throw 'Program Lock backup SHA-256 verification failed.' }
    return [pscustomobject]@{ Backup = $backup; Path = $resolved; PayloadSha256 = $expectedHash }
}

function Test-QuietShieldProgramLockAdministrator {
    [CmdletBinding()]
    param()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
