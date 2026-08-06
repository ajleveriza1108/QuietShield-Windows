[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param([switch]$ApprovedServiceStart, [string]$InstallRoot = 'D:\QuietShield\Service')
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ServiceActivation.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'QuietShieldService.Install.Common.ps1')
Assert-QuietShieldPowerShell51
$owned = Test-QuietShieldServiceOwnership -InstallRoot $InstallRoot
if ([string]$owned.Service.State -eq 'Running') { [pscustomobject]@{ status = 'AlreadyRunning'; changed = $false } | ConvertTo-Json -Compress; return }
if ($WhatIfPreference) { [pscustomobject]@{ status = 'WhatIfPassed'; wouldStartExactService = $true; modifyingCommandInvoked = $false } | ConvertTo-Json -Compress; return }
if (-not $ApprovedServiceStart) { throw 'Starting the service requires -ApprovedServiceStart.' }
if (-not (Test-QuietShieldAdministrator)) { throw 'Starting the service requires an already elevated Administrator console and never self-elevates.' }
if ($PSCmdlet.ShouldProcess('QuietShieldService', 'Start exact validated service')) { Start-Service -Name 'QuietShieldService' }
$service = Get-Service -Name 'QuietShieldService' -ErrorAction Stop
$service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(20))
[pscustomobject]@{ status = 'Running'; serviceName = $service.Name; displayName = $service.DisplayName; changed = $true } | ConvertTo-Json -Compress
