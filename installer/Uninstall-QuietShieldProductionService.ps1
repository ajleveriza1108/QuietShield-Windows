[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$ApprovedInstallerServiceUninstall,
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$ProductRoot,
    [Parameter(Mandatory = $true)][string]$StateRoot
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$sharedRoot = $PSScriptRoot
if (-not (Test-Path -LiteralPath (Join-Path $sharedRoot 'QuietShield.Script.Common.ps1') -PathType Leaf)) { $sharedRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\scripts')) }
. (Join-Path $sharedRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $sharedRoot 'ServiceActivation.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'QuietShield.Installer.Common.ps1')
Assert-QuietShieldPowerShell51

$layout = Get-QuietShieldProductionLayout -Version $Version
if (-not ([IO.Path]::GetFullPath($ProductRoot).TrimEnd('\')).Equals([string]$layout.ProductRoot, [StringComparison]::OrdinalIgnoreCase) -or
    -not ([IO.Path]::GetFullPath($StateRoot).TrimEnd('\')).Equals([string]$layout.StateRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Production uninstall is restricted to the exact Program Files and ProgramData QuietShield locations.'
}
$services = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='QuietShieldService'" -ErrorAction SilentlyContinue)
$ownershipExists = Test-Path -LiteralPath $layout.ServiceOwnershipPath -PathType Leaf
if ($services.Count -eq 0 -and -not $ownershipExists) {
    [pscustomobject]@{ status = 'AlreadyUninstalled'; changed = $false; broadFirewallCleanup = $false } | ConvertTo-Json -Compress
    return
}
if (-not $ownershipExists) { throw 'A foreign service uses the exact QuietShield service name; uninstall is refused.' }
$owned = Test-QuietShieldProductionOwnership -OwnershipPath $layout.ServiceOwnershipPath -AllowAbsentService
$plan = [pscustomobject][ordered]@{
    status = 'ProductionServiceUninstallPlanValidated'
    serviceName = 'QuietShieldService'
    exactOwnedService = $null -ne $owned.Service
    cleanupOnlyValidatedTransactionRules = $true
    broadFirewallCleanup = $false
    changesDns = $false
    productFilesRemovedByInstaller = $true
    stateEvidencePreserved = $true
    modifyingCommandInvoked = $false
}
if ($WhatIfPreference) { $plan | ConvertTo-Json -Depth 5; return }
if (-not $ApprovedInstallerServiceUninstall) { throw 'Production service uninstall requires explicit installer approval.' }
if (-not (Test-QuietShieldAdministrator)) { throw 'Production service uninstall requires the normal elevated Windows installer boundary and never self-elevates.' }

& (Join-Path $PSScriptRoot 'Restore-QuietShieldServiceState.ps1') -ApprovedEmergencyRestore -CleanupForUninstall -StateRoot $layout.StateRoot -Confirm:$false
if ($null -ne $owned.Service -and [string]$owned.Service.State -ne 'Stopped') {
    Stop-Service -Name 'QuietShieldService' -Force
    (Get-Service -Name 'QuietShieldService').WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
}
if ($null -ne $owned.Service) {
    & sc.exe delete 'QuietShieldService' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Exact QuietShield service deletion failed.' }
}
$deadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
while (@(Get-CimInstance -ClassName Win32_Service -Filter "Name='QuietShieldService'" -ErrorAction SilentlyContinue).Count -ne 0 -and [DateTimeOffset]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 250 }
if (@(Get-CimInstance -ClassName Win32_Service -Filter "Name='QuietShieldService'" -ErrorAction SilentlyContinue).Count -ne 0) { throw 'The exact QuietShield service remains after deletion.' }
Remove-Item -LiteralPath $layout.ServiceOwnershipPath -Force
Remove-Item -LiteralPath $layout.ProductionConfigurationPath -Force
[pscustomobject]@{ status = 'Uninstalled'; exactServiceAbsent = $true; exactOwnershipRemoved = $true; validatedRuleCleanupOnly = $true; stateEvidencePreserved = $true; restartRequired = $false } | ConvertTo-Json -Compress
