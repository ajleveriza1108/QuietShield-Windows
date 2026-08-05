[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$StatePath = '',
    [string]$BackupPath = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'DnsTransaction.Script.Common.ps1')

Assert-QuietShieldPowerShell51
$root = Get-QuietShieldRepositoryRoot
if ([string]::IsNullOrWhiteSpace($StatePath)) {
    $StatePath = Join-Path $root 'artifacts\dns-transaction\state.json'
}

$result = [ordered]@{
    schemaVersion = 1
    status = 'PreviewOnly'
    statePath = [System.IO.Path]::GetFullPath($StatePath)
    stateAvailable = $false
    backupValidated = $false
    modifyingImplementationInvoked = $false
    message = 'No activation can occur from this dry-run script.'
}

if (Test-Path -LiteralPath $StatePath -PathType Leaf) {
    $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    foreach ($property in @('schemaVersion', 'productMarker', 'purpose', 'transactionId', 'state')) {
        if (-not (Test-QuietShieldJsonProperty -Object $state -Name $property)) {
            throw ('The DNS transaction state is malformed; missing: ' + $property)
        }
    }
    if ([int]$state.schemaVersion -ne 1 -or [string]$state.productMarker -cne 'QuietShield' -or [string]$state.purpose -cne 'DnsTransactionState') {
        throw 'The DNS transaction state file is not recognized.'
    }
    [void]([Guid]$state.transactionId)
    $allowedStates = @('Created', 'PreflightPassed', 'BackupValidated', 'ReadyForApproval', 'Applying', 'Verifying', 'Committed', 'RollbackRequired', 'RollingBack', 'RolledBack', 'Interrupted', 'RecoveryRequired', 'Failed')
    if ($allowedStates -notcontains [string]$state.state) {
        throw 'The DNS transaction state value is invalid.'
    }
    $result.stateAvailable = $true
    $result.transactionState = [string]$state.state
}

if (-not [string]::IsNullOrWhiteSpace($BackupPath)) {
    $validated = Test-QuietShieldDnsBackup -BackupPath $BackupPath
    $result.backupValidated = $true
    $result.backupPath = $validated.Path
}

if ($PSCmdlet.ShouldProcess('QuietShield DNS transaction plan', 'Preview readiness without applying DNS changes')) {
    $result.message = 'The transaction plan is structurally valid for preview. Explicit approval, Administrator context, active resolver verification, and a deadline are still required.'
}

[pscustomobject]$result | ConvertTo-Json -Depth 6
