[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$BackupPath = '',
    [switch]$ExplicitUserApproval
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ProgramLockTransaction.Script.Common.ps1')

Assert-QuietShieldPowerShell51
$root = Get-QuietShieldRepositoryRoot
if ([string]::IsNullOrWhiteSpace($BackupPath)) { $BackupPath = Join-Path $root 'tests\Fixtures\phase8-program-lock-backup.json' }
$validated = Test-QuietShieldProgramLockBackup -BackupPath $BackupPath
$ownedRuleCount = @($validated.Backup.quietShieldOwnedRules).Count

if ($WhatIfPreference) {
    [pscustomobject]@{
        Status = 'WhatIfPassed'
        BackupValidated = $true
        QuietShieldOwnedRuleCount = $ownedRuleCount
        WouldRestoreOnlyValidatedQuietShieldOwnedRules = $true
        ModifyingImplementationAvailable = $false
        SafetyStatement = 'Phase 8 performs no modifying command.'
    } | Format-List
    return
}

if (-not $ExplicitUserApproval) { throw 'Future real restore requires -ExplicitUserApproval.' }
if (-not (Test-QuietShieldProgramLockAdministrator)) { throw 'Future real restore requires an already elevated Administrator console; this script never self-elevates.' }
if ($PSCmdlet.ShouldProcess('validated QuietShield-owned Program Lock rules', 'Restore exact backup state')) {
    throw 'Phase 8 has no modifying Windows implementation. Restore was validated but deliberately not executed.'
}
