[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$StatePath,
    [Parameter(Mandatory = $true)][int]$OrchestratorProcessId,
    [Parameter(Mandatory = $true)][string]$HeartbeatPath,
    [Parameter(Mandatory = $true)][string]$RollbackRequestPath,
    [Parameter(Mandatory = $true)][string]$VerificationFailurePath,
    [Parameter(Mandatory = $true)][string]$ProbeFailurePath,
    [Parameter(Mandatory = $true)][string]$StopPath,
    [Parameter(Mandatory = $true)][string]$EvidencePath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ProgramLockRehearsal.Script.Common.ps1')

Assert-QuietShieldPowerShell51
if (-not (Test-QuietShieldAdministrator)) { throw 'The independent rehearsal watchdog must inherit an already elevated Administrator context.' }
$restoreScript = Join-Path $PSScriptRoot 'Restore-ProgramLockRehearsal.ps1'
Add-QuietShieldProgramLockRehearsalEvidence -EvidencePath $EvidencePath -Entry ([ordered]@{
    schemaVersion = 1; productMarker = 'QuietShield'; purpose = 'ProgramLockFirewallRehearsalEvidence'; event = 'WatchdogStarted'; timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
})

while ($true) {
    $validated = Test-QuietShieldProgramLockRehearsalState -StatePath $StatePath -AllowCompleted
    $state = $validated.State
    if ([bool]$state.completed -or (Test-Path -LiteralPath $StopPath -PathType Leaf)) { break }
    $exactRule = Get-QuietShieldExactProgramLockRehearsalRule -RuleName ([string]$state.rule.name)
    $parentAlive = $null -ne (Get-Process -Id $OrchestratorProcessId -ErrorAction SilentlyContinue)
    $ruleCreated = $null -ne $exactRule -or [string]$state.state -in @('RuleCreated','RuleVerified','BlockVerified','RehearsalActive','RollbackStarted')
    if (-not $ruleCreated -and -not $parentAlive) { break }
    $heartbeatExists = Test-Path -LiteralPath $HeartbeatPath -PathType Leaf
    $heartbeatLastWriteTime = $null
    if ($heartbeatExists) {
        $heartbeatLastWriteTime = (Get-Item -LiteralPath $HeartbeatPath).LastWriteTimeUtc
    }
    $trigger = Get-QuietShieldProgramLockWatchdogTrigger `
        -RuleCreated $ruleCreated `
        -ParentAlive $parentAlive `
        -CurrentTime ([DateTimeOffset]::UtcNow) `
        -Deadline $state.expiresAtUtc `
        -RollbackRequested (Test-Path -LiteralPath $RollbackRequestPath -PathType Leaf) `
        -VerificationFailed (Test-Path -LiteralPath $VerificationFailurePath -PathType Leaf) `
        -ProbeFailed (Test-Path -LiteralPath $ProbeFailurePath -PathType Leaf) `
        -HeartbeatExists $heartbeatExists `
        -HeartbeatLastWriteTime $heartbeatLastWriteTime
    if ($null -ne $trigger) {
        Add-QuietShieldProgramLockRehearsalEvidence -EvidencePath $EvidencePath -Entry ([ordered]@{
            schemaVersion = 1; productMarker = 'QuietShield'; purpose = 'ProgramLockFirewallRehearsalEvidence'; transactionId = [string]$state.transactionId;
            event = 'WatchdogRollbackTriggered'; trigger = $trigger; timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        })
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $restoreScript -StatePath $StatePath -ApprovedWatchdogCleanup -EvidencePath $EvidencePath
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        break
    }
    Start-Sleep -Milliseconds 500
}

$final = Test-QuietShieldProgramLockRehearsalState -StatePath $StatePath -AllowCompleted
if ($null -ne (Get-QuietShieldExactProgramLockRehearsalRule -RuleName ([string]$final.State.rule.name))) { throw 'The watchdog stopped while the exact rehearsal rule remained.' }
Add-QuietShieldProgramLockRehearsalEvidence -EvidencePath $EvidencePath -Entry ([ordered]@{
    schemaVersion = 1; productMarker = 'QuietShield'; purpose = 'ProgramLockFirewallRehearsalEvidence'; transactionId = [string]$final.State.transactionId;
    event = 'WatchdogStoppedAfterVerifiedCleanup'; timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
})
