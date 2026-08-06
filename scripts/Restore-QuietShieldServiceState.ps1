[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$ApprovedEmergencyRestore,
    [switch]$CleanupForUninstall,
    [Guid]$TransactionId = [Guid]::Empty,
    [string]$StateRoot = 'D:\QuietShield\State'
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ServiceActivation.Script.Common.ps1')
Assert-QuietShieldPowerShell51
$state = [IO.Path]::GetFullPath($StateRoot).TrimEnd('\')
if (-not $state.StartsWith('D:\QuietShield\', [StringComparison]::OrdinalIgnoreCase)) { throw 'The service state root must remain under D:\QuietShield.' }
$transactionDirectory = Join-Path $state 'transactions'
$transactionFiles = @()
if (Test-Path -LiteralPath $transactionDirectory -PathType Container) { $transactionFiles = @(Get-ChildItem -LiteralPath $transactionDirectory -Filter '*.json' -File | Sort-Object -Property Name) }
if ($TransactionId -ne [Guid]::Empty) { $transactionFiles = @($transactionFiles | Where-Object { $_.BaseName -ceq $TransactionId.ToString('D') }) }
if (-not $CleanupForUninstall -and $TransactionId -eq [Guid]::Empty -and -not $WhatIfPreference) { throw 'Emergency restore requires the exact approved transaction ID.' }
$validatedTransactions = @()
foreach ($file in $transactionFiles) { $validatedTransactions += Test-QuietShieldFirewallTransaction -Path $file.FullName }
if ($TransactionId -ne [Guid]::Empty -and $validatedTransactions.Count -ne 1) { throw 'The exact approved transaction record was not found exactly once.' }
$operation = 'Restore'
if ($CleanupForUninstall) { $operation = 'Cleanup' }
$plan = [pscustomobject]@{ status = 'WhatIfPassed'; operation = $operation; exactTransactionCount = $validatedTransactions.Count; exactRuleNames = @($validatedTransactions | ForEach-Object { [string]$_.Transaction.ruleName } | Sort-Object -Unique); modifyingCommandInvoked = $false }
if ($WhatIfPreference) { $plan | ConvertTo-Json -Depth 5; return }
if (-not $ApprovedEmergencyRestore) { throw 'Exact service state restoration requires -ApprovedEmergencyRestore.' }
if (-not (Test-QuietShieldAdministrator)) { throw 'Exact service state restoration requires an already elevated Administrator console and never self-elevates.' }
foreach ($validated in $validatedTransactions) {
    if ($PSCmdlet.ShouldProcess([string]$validated.Transaction.ruleName, ($operation + ' exact validated QuietShield service rule state'))) {
        & (Join-Path $PSScriptRoot 'Invoke-ServiceFirewallPolicy.ps1') -Operation $operation -TransactionPath $validated.Path -ApprovedServiceEnforcement -Confirm:$false
    }
}
[pscustomobject]@{ status = 'Completed'; operation = $operation; exactTransactionCount = $validatedTransactions.Count; broadRuleEnumerationUsed = $false } | ConvertTo-Json -Compress
