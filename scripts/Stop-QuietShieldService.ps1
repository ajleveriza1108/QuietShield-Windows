[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param([switch]$ApprovedServiceStop, [string]$InstallRoot = 'D:\QuietShield\Service')
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ServiceActivation.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'QuietShieldService.Install.Common.ps1')
Assert-QuietShieldPowerShell51
$owned = Test-QuietShieldServiceOwnership -InstallRoot $InstallRoot
if ([string]$owned.Service.State -eq 'Stopped') { [pscustomobject]@{ status = 'AlreadyStopped'; changed = $false } | ConvertTo-Json -Compress; return }
if ($WhatIfPreference) { [pscustomobject]@{ status = 'WhatIfPassed'; wouldStopExactService = $true; modifyingCommandInvoked = $false } | ConvertTo-Json -Compress; return }
if (-not $ApprovedServiceStop) { throw 'Stopping the service requires -ApprovedServiceStop.' }
if (-not (Test-QuietShieldAdministrator)) { throw 'Stopping the service requires an already elevated Administrator console and never self-elevates.' }
if ($PSCmdlet.ShouldProcess('QuietShieldService', 'Stop exact validated service')) { Stop-Service -Name 'QuietShieldService' }
$service = Get-Service -Name 'QuietShieldService' -ErrorAction Stop
$service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(20))
[pscustomobject]@{ status = 'Stopped'; serviceName = $service.Name; changed = $true } | ConvertTo-Json -Compress
