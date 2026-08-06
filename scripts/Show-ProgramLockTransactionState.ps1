[CmdletBinding()]
param([string]$BackupPath = '')

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ProgramLockTransaction.Script.Common.ps1')

Assert-QuietShieldPowerShell51
Assert-QuietShieldNonElevated
$root = Get-QuietShieldRepositoryRoot
if ([string]::IsNullOrWhiteSpace($BackupPath)) { $BackupPath = Join-Path $root 'tests\Fixtures\phase8-program-lock-backup.json' }
$validated = Test-QuietShieldProgramLockBackup -BackupPath $BackupPath
[pscustomobject]@{
    State = 'Draft'
    TransactionId = [string]$validated.Backup.transactionId
    ActiveProfile = [string]$validated.Backup.activeProfileId
    OwnedRuleBackupCount = @($validated.Backup.quietShieldOwnedRules).Count
    BackupSha256 = $validated.PayloadSha256
    CanExecute = $false
    Status = 'Read-only Phase 8 transaction state; enforcement is not active.'
} | Format-List
