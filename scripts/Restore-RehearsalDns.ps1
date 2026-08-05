[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$BackupPath,
    [Parameter(Mandatory = $true)]
    [switch]$ApprovedRollbackFromRehearsal,
    [Parameter(Mandatory = $true)]
    [string]$RollbackReason
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'DnsTransaction.Script.Common.ps1')

Assert-QuietShieldPowerShell51
if (-not $ApprovedRollbackFromRehearsal) { throw 'The watchdog-approved rehearsal rollback switch is required.' }
if (-not (Test-QuietShieldAdministrator)) { throw 'Rehearsal rollback requires inherited Administrator context and never self-elevates.' }
$validated = Test-QuietShieldRehearsalBackup -BackupPath $BackupPath
$adapter = Test-QuietShieldAdapterIsExactRehearsalMatch -Backup $validated.Backup

foreach ($family in @($validated.Backup.adapter.families)) {
    if (-not [bool]$family.enabled) { continue }
    $familyNumber = if ([string]$family.addressFamily -ceq 'IPv4') { 2 } else { 23 }
    $inputObject = @(Get-DnsClientServerAddress -InterfaceIndex ([int]$adapter.InterfaceIndex) -ErrorAction Stop | Where-Object { [int]$_.AddressFamily -eq $familyNumber })
    if ($inputObject.Count -ne 1) { throw ('The current adapter DNS family could not be matched: ' + [string]$family.addressFamily) }
    $target = 'validated rehearsal backup ' + [string]$validated.Backup.backupId + ' on InterfaceIndex ' + [string]$adapter.InterfaceIndex + ' ' + [string]$family.addressFamily
    if ([bool]$family.automatic) {
        if ($PSCmdlet.ShouldProcess($target, 'Restore automatic DNS assignment')) {
            Set-DnsClientServerAddress -InputObject $inputObject[0] -ResetServerAddresses -Confirm:$false -ErrorAction Stop
        }
    }
    else {
        $servers = @($family.serverAddresses | ForEach-Object { [string]$_ })
        if ($servers.Count -eq 0) { throw 'The validated static rehearsal backup contains no original DNS values.' }
        if ($PSCmdlet.ShouldProcess($target, 'Restore exact original DNS addresses')) {
            Set-DnsClientServerAddress -InputObject $inputObject[0] -ServerAddresses $servers -Confirm:$false -ErrorAction Stop
        }
    }
}

if (-not $WhatIfPreference) {
    Clear-DnsClientCache -ErrorAction Stop
    $verificationDeadline = [DateTimeOffset]::UtcNow.AddSeconds(15)
    $verificationError = 'Post-restore DNS verification did not run.'
    $verified = $false
    while ([DateTimeOffset]::UtcNow -lt $verificationDeadline -and -not $verified) {
        $verified = $true
        foreach ($family in @($validated.Backup.adapter.families)) {
            if (-not [bool]$family.enabled) { continue }
            $familyNumber = if ([string]$family.addressFamily -ceq 'IPv4') { 2 } else { 23 }
            $current = @(Get-DnsClientServerAddress -InterfaceIndex ([int]$adapter.InterfaceIndex) -ErrorAction Stop | Where-Object { [int]$_.AddressFamily -eq $familyNumber })
            if ($current.Count -ne 1) {
                $verified = $false
                $verificationError = 'Post-restore DNS family verification failed.'
                break
            }
            $automatic = Test-QuietShieldDnsFamilyIsAutomatic -InterfaceGuid ([Guid]$adapter.InterfaceGuid) -AddressFamily ([string]$family.addressFamily)
            if ($automatic -ne [bool]$family.automatic) {
                $verified = $false
                $verificationError = 'Original DNS mode was not restored for ' + [string]$family.addressFamily
                break
            }
            if (-not (Test-QuietShieldStringArrayExact -Expected @($family.serverAddresses) -Actual @($current[0].ServerAddresses))) {
                $verified = $false
                $verificationError = 'Original DNS server values were not restored exactly for ' + [string]$family.addressFamily
                break
            }
        }
        if (-not $verified) { Start-Sleep -Milliseconds 500 }
    }
    if (-not $verified) { throw $verificationError }
}

[pscustomobject]@{
    schemaVersion = 1
    status = $(if ($WhatIfPreference) { 'WhatIfValidated' } else { 'RestoredAndVerified' })
    backupId = [string]$validated.Backup.backupId
    rehearsalId = [string]$validated.Backup.rehearsalId
    rollbackReason = $RollbackReason
    adapterGuid = ([Guid]$adapter.InterfaceGuid).ToString('D')
    interfaceIndex = [int]$adapter.InterfaceIndex
    selfElevated = $false
    inventedDnsValues = $false
} | ConvertTo-Json -Depth 4
