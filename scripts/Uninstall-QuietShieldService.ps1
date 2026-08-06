[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$ApprovedServiceUninstall,
    [string]$InstallRoot = 'D:\QuietShield\Service',
    [string]$StateRoot = 'D:\QuietShield\State'
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ServiceActivation.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'QuietShieldService.Install.Common.ps1')
Assert-QuietShieldPowerShell51
$install = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
if (-not $install.StartsWith('D:\QuietShield\', [StringComparison]::OrdinalIgnoreCase)) { throw 'The service installation root must remain under D:\QuietShield.' }
$services = @(Get-QuietShieldExactService)
if ($services.Count -eq 0 -and -not (Test-Path -LiteralPath (Join-Path $install 'service-ownership.json') -PathType Leaf)) { [pscustomobject]@{ status = 'AlreadyUninstalled'; changed = $false } | ConvertTo-Json -Compress; return }
$owned = Test-QuietShieldServiceOwnership -InstallRoot $install -AllowAbsentService
$plan = [pscustomobject]@{ status = 'WhatIfPassed'; exactOwnedService = ($null -ne $owned.Service); wouldStopExactService = ($null -ne $owned.Service -and [string]$owned.Service.State -ne 'Stopped'); wouldCleanupOnlyValidatedTransactionRules = $true; wouldDeleteExactService = ($null -ne $owned.Service); wouldRemoveInstallRoot = $true; preserveStateEvidence = $true; modifyingCommandInvoked = $false }
if ($WhatIfPreference) { $plan | ConvertTo-Json -Depth 5; return }
if (-not $ApprovedServiceUninstall) { throw 'Service uninstallation requires -ApprovedServiceUninstall.' }
if (-not (Test-QuietShieldAdministrator)) { throw 'Service uninstallation requires an already elevated Administrator console and never self-elevates.' }
& (Join-Path $PSScriptRoot 'Restore-QuietShieldServiceState.ps1') -ApprovedEmergencyRestore -CleanupForUninstall -StateRoot $StateRoot -Confirm:$false
if ($null -ne $owned.Service -and [string]$owned.Service.State -ne 'Stopped') {
    if ($PSCmdlet.ShouldProcess('QuietShieldService', 'Stop exact owned service before uninstall')) { Stop-Service -Name 'QuietShieldService' -Force }
    (Get-Service -Name 'QuietShieldService').WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(20))
}
if ($null -ne $owned.Service -and $PSCmdlet.ShouldProcess('QuietShieldService', 'Delete exact owned service registration')) {
    & sc.exe delete 'QuietShieldService' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Exact QuietShield service deletion failed.' }
}
$deadline = [DateTimeOffset]::UtcNow.AddSeconds(20)
while (@(Get-QuietShieldExactService).Count -ne 0 -and [DateTimeOffset]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 250 }
if (@(Get-QuietShieldExactService).Count -ne 0) { throw 'The exact QuietShield service remains after deletion.' }
if ($PSCmdlet.ShouldProcess($install, 'Remove exact validated QuietShield service package')) { Remove-Item -LiteralPath $install -Recurse -Force }
if (Test-Path -LiteralPath $install) { throw 'The exact QuietShield service package remains after uninstall.' }
[pscustomobject]@{ status = 'Uninstalled'; serviceAbsent = $true; installRootAbsent = $true; stateEvidencePreserved = (Test-Path -LiteralPath ([IO.Path]::GetFullPath($StateRoot))); restartRequired = $false } | ConvertTo-Json -Compress
