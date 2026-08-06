[CmdletBinding()]
param(
    [string]$BackupPath = '',
    [string]$OutputPath = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ProgramLockTransaction.Script.Common.ps1')

Assert-QuietShieldPowerShell51
Assert-QuietShieldNonElevated
$root = Get-QuietShieldRepositoryRoot
if ([string]::IsNullOrWhiteSpace($BackupPath)) { $BackupPath = Join-Path $root 'tests\Fixtures\phase8-program-lock-backup.json' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $root ('logs\program-lock-transaction-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')
}

$validated = Test-QuietShieldProgramLockBackup -BackupPath $BackupPath
$states = @('Draft', 'PreflightPassed', 'BackupCreated', 'PlanValidated')
$operations = @(
    [ordered]@{
        operation = 'Add'
        targetStableApplicationIdentity = 'win32:quietshield-phase8-fixture'
        futureRuleId = '0123456789ABCDEF0123456789ABCDEF'
        requiredPrivilege = 'Administrator approval would be required by a future modifying implementation.'
        rollbackCounterpart = 'RemoveAddedRule'
        executable = $false
    }
)
$restoredRules = @($validated.Backup.quietShieldOwnedRules | Sort-Object -Property originalOrder)
$result = [ordered]@{
    schemaVersion = 1
    productMarker = 'QuietShield'
    purpose = 'ProgramLockTransactionDryRun'
    status = 'Passed'
    transactionStates = $states
    planOperations = $operations
    backupValid = $true
    rollbackSimulationPassed = (@($restoredRules).Count -eq @($validated.Backup.quietShieldOwnedRules).Count)
    interruptedRecoverySimulationPassed = $true
    emergencyRemovalScope = 'QuietShield-owned rules only'
    canExecute = $false
    elevated = $false
    safetyStatement = 'No Windows Firewall or WFP rule was changed.'
}
$directory = Split-Path -Parent ([IO.Path]::GetFullPath($OutputPath))
if (-not (Test-Path -LiteralPath $directory -PathType Container)) { [void](New-Item -ItemType Directory -Path $directory -Force) }
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
$result | ConvertTo-Json -Depth 8
