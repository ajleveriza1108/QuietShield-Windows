[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$BackupPath,
    [switch]$ExplicitUserApproval
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'DnsTransaction.Script.Common.ps1')

Assert-QuietShieldPowerShell51
$validated = Test-QuietShieldDnsBackup -BackupPath $BackupPath
[void](Test-QuietShieldDnsAdapterIdentities -Backup $validated.Backup)

if (-not $WhatIfPreference) {
    if (-not $ExplicitUserApproval) {
        throw 'Emergency DNS restoration requires the -ExplicitUserApproval switch.'
    }
    if (-not (Test-QuietShieldAdministrator)) {
        throw 'Emergency DNS restoration requires Administrator rights. This script never self-elevates.'
    }
}

foreach ($adapter in @($validated.Backup.adapters)) {
    $interfaceIndex = [int]$adapter.identity.interfaceIndex
    $target = "InterfaceIndex $interfaceIndex from validated backup $($validated.Backup.backupId)"
    if ([bool]$adapter.automatic) {
        if ($PSCmdlet.ShouldProcess($target, 'Restore automatic DNS server assignment')) {
            Set-DnsClientServerAddress -InterfaceIndex $interfaceIndex -ResetServerAddresses -Confirm:$false -ErrorAction Stop
        }
    }
    else {
        $originalServers = @($adapter.serverAddresses | ForEach-Object { [string]$_ })
        if ($originalServers.Count -eq 0) {
            throw 'The validated static backup unexpectedly contains no original DNS values.'
        }
        if ($PSCmdlet.ShouldProcess($target, 'Restore exact original DNS server addresses')) {
            Set-DnsClientServerAddress -InterfaceIndex $interfaceIndex -ServerAddresses $originalServers -Confirm:$false -ErrorAction Stop
        }
    }
}

[pscustomobject]@{
    schemaVersion = 1
    status = $(if ($WhatIfPreference) { 'WhatIfValidated' } else { 'RestoreRequested' })
    backupId = [string]$validated.Backup.backupId
    adapterCount = @($validated.Backup.adapters).Count
    selfElevated = $false
    inventedDnsValues = $false
} | ConvertTo-Json -Depth 4
