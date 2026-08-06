[CmdletBinding()]
param([string]$StatePath = '')

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ProgramLockRehearsal.Script.Common.ps1')
Assert-QuietShieldPowerShell51
Assert-QuietShieldNonElevated
$root = Get-QuietShieldRepositoryRoot
if ([string]::IsNullOrWhiteSpace($StatePath)) { $StatePath = Join-Path $root 'artifacts\program-lock-rehearsal\current.json' }
$validated = Test-QuietShieldProgramLockRehearsalState -StatePath $StatePath -AllowCompleted
$state = $validated.State
[pscustomobject]@{
    TransactionId = [string]$state.transactionId
    State = [string]$state.state
    Completed = [bool]$state.completed
    ExactRuleName = [string]$state.rule.name
    ProbePath = [string]$state.rule.programPath
    Endpoint = ([string]$state.rule.remoteAddress + ':' + [string]$state.rule.remotePort)
    ExpiresAtUtc = [string]$state.expiresAtUtc
    PayloadSha256 = $validated.PayloadSha256
} | Format-List
