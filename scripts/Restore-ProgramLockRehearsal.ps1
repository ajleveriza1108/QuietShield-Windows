[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][string]$StatePath,
    [switch]$ApprovedOrchestratorRollback,
    [switch]$ApprovedWatchdogCleanup,
    [string]$EvidencePath = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ProgramLockRehearsal.Script.Common.ps1')

Assert-QuietShieldPowerShell51
$validated = Test-QuietShieldProgramLockRehearsalState -StatePath $StatePath
$state = $validated.State
if ($WhatIfPreference) {
    $rule = Get-QuietShieldExactProgramLockRehearsalRule -RuleName ([string]$state.rule.name)
    [pscustomobject]@{
        status = 'WhatIfPassed'
        transactionValidated = $true
        exactRuleName = [string]$state.rule.name
        exactRuleCurrentlyPresent = ($null -ne $rule)
        wouldRemoveOnlyExactRecordedRule = $true
        modifyingCommandInvoked = $false
    } | Format-List
    return
}

if (-not $ApprovedOrchestratorRollback -and -not $ApprovedWatchdogCleanup) { throw 'Exact rehearsal rollback requires ApprovedOrchestratorRollback or ApprovedWatchdogCleanup.' }
if (-not (Test-QuietShieldAdministrator)) { throw 'Exact rehearsal rollback requires an already elevated Administrator console; this script never self-elevates.' }
$rollbackEligibleStates = @('RuleCreated', 'RuleVerified', 'BlockVerified', 'RehearsalActive', 'RollbackStarted', 'RuleRemoved')
if ([string]$state.state -notin $rollbackEligibleStates) { throw ('The rehearsal transaction is not eligible for exact rollback from state: ' + [string]$state.state) }
$rollbackMutex = New-Object Threading.Mutex($false, ('Local\QuietShield.ProgramLock.Rehearsal.' + [string]$state.transactionId))
$rollbackLockTaken = $false
try {
    $rollbackLockTaken = $rollbackMutex.WaitOne([TimeSpan]::FromSeconds(15))
    if (-not $rollbackLockTaken) { throw 'Timed out waiting for exclusive exact-rule rollback ownership.' }

    $validated = Test-QuietShieldProgramLockRehearsalState -StatePath $StatePath
    $state = $validated.State
    if ([string]$state.state -notin $rollbackEligibleStates) { throw ('The revalidated rehearsal transaction is not eligible for exact rollback from state: ' + [string]$state.state) }
    $rule = Get-QuietShieldExactProgramLockRehearsalRule -RuleName ([string]$state.rule.name)
    if ($null -ne $rule) {
        [void](Test-QuietShieldExactProgramLockRehearsalRuleProperties -State $state -Rule $rule)
        $previousConfirmPreference = $ConfirmPreference
        try {
            $ConfirmPreference = 'None'
            if ($PSCmdlet.ShouldProcess([string]$state.rule.name, 'Remove exact QuietShield rehearsal rule')) {
                Remove-NetFirewallRule -Name ([string]$state.rule.name) -Confirm:$false
            }
        }
        finally {
            $ConfirmPreference = $previousConfirmPreference
        }
    }
    if ($null -ne (Get-QuietShieldExactProgramLockRehearsalRule -RuleName ([string]$state.rule.name))) { throw 'The exact rehearsal rule remains after rollback.' }
    [void](Set-QuietShieldProgramLockRehearsalState -State $state -StatePath $StatePath -NewState 'RuleRemoved')
    if (-not [string]::IsNullOrWhiteSpace($EvidencePath)) {
        Add-QuietShieldProgramLockRehearsalEvidence -EvidencePath $EvidencePath -Entry ([ordered]@{
            schemaVersion = 1; productMarker = 'QuietShield'; purpose = 'ProgramLockFirewallRehearsalEvidence';
            transactionId = [string]$state.transactionId; event = 'ExactRuleRemoved'; ruleName = [string]$state.rule.name; timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        })
    }
}
finally {
    if ($rollbackLockTaken) { $rollbackMutex.ReleaseMutex() }
    $rollbackMutex.Dispose()
}
