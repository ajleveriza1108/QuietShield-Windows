[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Query','Blocked','AllowedOnAll','Restore','Cleanup')][string]$Operation,
    [string]$TransactionPath = '',
    [string]$RuleName = '',
    [switch]$ApprovedServiceEnforcement
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ServiceActivation.Script.Common.ps1')
Assert-QuietShieldPowerShell51

function Get-ExactRuleSnapshot {
    param([Parameter(Mandatory = $true)][string]$ExactName)
    $rules = @(Get-NetFirewallRule -Name $ExactName -ErrorAction SilentlyContinue)
    if ($rules.Count -gt 1) { throw 'The exact Firewall rule identity is ambiguous.' }
    if ($rules.Count -eq 0) { return $null }
    $rule = $rules[0]
    $application = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule
    $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule
    $address = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule
    $owner = 'Foreign'
    $schema = 0
    if ([string]$rule.Name -like 'QuietShield.ProgramLock.*' -and [string]$rule.Description -match '\AQuietShield Program Lock; schema=1; id=[0-9a-f]{32}; owner=QuietShield\z') { $owner = 'QuietShield'; $schema = 1 }
    $remotePort = 0
    if ([string]$port.RemotePort -match '\A[0-9]+\z') { $remotePort = [int]$port.RemotePort }
    return [pscustomobject][ordered]@{
        ownershipMarker = $owner; schemaVersion = $schema; name = [string]$rule.Name; description = [string]$rule.Description;
        programPath = [IO.Path]::GetFullPath([string]$application.Program); enabled = ([string]$rule.Enabled -eq 'True'); direction = [string]$rule.Direction;
        action = [string]$rule.Action; profile = [string]$rule.Profile; protocol = [string]$port.Protocol; remoteAddress = [string]$address.RemoteAddress; remotePort = $remotePort
    }
}

if ($Operation -eq 'Query') {
    if ([string]::IsNullOrWhiteSpace($RuleName) -or $RuleName -notmatch '\AQuietShield\.ProgramLock\.[0-9a-f]{32}\z') { throw 'An exact deterministic QuietShield rule name is required.' }
    $snapshot = Get-ExactRuleSnapshot -ExactName $RuleName
    [pscustomobject]@{ status = 'QueryCompleted'; present = ($null -ne $snapshot); rule = $snapshot } | ConvertTo-Json -Depth 8 -Compress
    return
}

$validated = Test-QuietShieldFirewallTransaction -Path $TransactionPath -AllowHistoricalProgramIdentityForCleanup:($Operation -eq 'Cleanup')
$transaction = $validated.Transaction
if ($Operation -ne 'Restore' -and $Operation -ne 'Cleanup' -and [string]$transaction.policy -cne $Operation) { throw 'The requested operation does not match the immutable transaction policy.' }
if ($WhatIfPreference) {
    [pscustomobject]@{ status = 'WhatIfPassed'; operation = $Operation; exactRuleName = [string]$transaction.ruleName; modifyingCommandInvoked = $false } | ConvertTo-Json -Compress
    return
}
if (-not $ApprovedServiceEnforcement) { throw 'The exact Firewall operation requires -ApprovedServiceEnforcement.' }
if (-not (Test-QuietShieldAdministrator)) { throw 'The exact Firewall operation requires Administrator rights and never self-elevates.' }

# LocalSystem launches this helper with -NonInteractive. The immutable transaction,
# explicit service-enforcement approval, and Administrator gates have already passed.
$ConfirmPreference = 'None'

$current = Get-ExactRuleSnapshot -ExactName ([string]$transaction.ruleName)
if ($null -ne $current -and ([string]$current.ownershipMarker -cne 'QuietShield' -or [string]$current.name -cne [string]$transaction.ruleName)) { throw 'A foreign exact-name Firewall rule collision was refused.' }
if ($null -ne $current -and [IO.Path]::GetFullPath([string]$current.programPath) -cne [IO.Path]::GetFullPath([string]$transaction.programPath)) { throw 'The exact rule targets a different program and was refused.' }

if ($Operation -eq 'Blocked') {
    if ($null -eq $current -and $PSCmdlet.ShouldProcess([string]$transaction.ruleName, 'Create exact QuietShield outbound block rule')) {
        New-NetFirewallRule -Name ([string]$transaction.ruleName) -DisplayName ([string]$transaction.ruleName) -Description ([string]$transaction.description) -Direction Outbound -Action Block -Enabled True -Profile Any -Program ([string]$transaction.programPath) -Protocol Any | Out-Null
    }
}
elseif ($Operation -eq 'AllowedOnAll' -or $Operation -eq 'Cleanup') {
    if ($null -ne $current -and $PSCmdlet.ShouldProcess([string]$transaction.ruleName, 'Remove exact validated QuietShield-owned block rule')) {
        $previousConfirmPreference = $ConfirmPreference
        try { $ConfirmPreference = 'None'; Remove-NetFirewallRule -Name ([string]$transaction.ruleName) -Confirm:$false }
        finally { $ConfirmPreference = $previousConfirmPreference }
    }
}
elseif ($Operation -eq 'Restore') {
    if ($null -ne $current -and $PSCmdlet.ShouldProcess([string]$transaction.ruleName, 'Remove exact current QuietShield rule before restore')) {
        $previousConfirmPreference = $ConfirmPreference
        try { $ConfirmPreference = 'None'; Remove-NetFirewallRule -Name ([string]$transaction.ruleName) -Confirm:$false }
        finally { $ConfirmPreference = $previousConfirmPreference }
    }
    if ($null -ne $transaction.backupRule -and $PSCmdlet.ShouldProcess([string]$transaction.ruleName, 'Restore exact backed-up QuietShield rule')) {
        $backup = $transaction.backupRule
        $protocol = [string]$backup.protocol
        $restoreArguments = @{
            Name = [string]$backup.name; DisplayName = [string]$backup.name; Description = [string]$backup.description
            Direction = [string]$backup.direction; Action = [string]$backup.action; Enabled = [bool]$backup.enabled
            Profile = [string]$backup.profile; Program = [string]$backup.programPath; Protocol = $protocol
            RemoteAddress = [string]$backup.remoteAddress
        }
        if ($protocol -in @('TCP','UDP') -and [int]$backup.remotePort -gt 0) { $restoreArguments.RemotePort = [string][int]$backup.remotePort }
        New-NetFirewallRule @restoreArguments | Out-Null
    }
}

$after = Get-ExactRuleSnapshot -ExactName ([string]$transaction.ruleName)
if ($Operation -eq 'Blocked' -and ($null -eq $after -or [string]$after.ownershipMarker -cne 'QuietShield' -or [string]$after.description -cne [string]$transaction.description -or [string]$after.action -cne 'Block' -or [string]$after.direction -cne 'Outbound')) { throw 'Exact Blocked rule verification failed.' }
if (($Operation -eq 'AllowedOnAll' -or $Operation -eq 'Cleanup') -and $null -ne $after) { throw 'The exact QuietShield block rule remains.' }
if ($Operation -eq 'Restore' -and (($null -eq $transaction.backupRule -and $null -ne $after) -or ($null -ne $transaction.backupRule -and $null -eq $after))) { throw 'Exact rollback verification failed.' }
[pscustomobject]@{ status = 'Completed'; present = ($null -ne $after); rule = $after } | ConvertTo-Json -Depth 8 -Compress
