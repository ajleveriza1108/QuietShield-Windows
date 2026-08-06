[CmdletBinding()]
param([switch]$ApprovedServiceTest, [string]$InstallRoot = 'D:\QuietShield\Service', [string]$OutputPath = '')
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ServiceActivation.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'QuietShieldService.Install.Common.ps1')
Assert-QuietShieldPowerShell51
if (-not $ApprovedServiceTest) { throw 'Service validation requires -ApprovedServiceTest.' }
if (-not (Test-QuietShieldAdministrator)) { throw 'Service validation requires an already elevated Administrator console and never self-elevates.' }
$owned = Test-QuietShieldServiceOwnership -InstallRoot $InstallRoot
if ([string]$owned.Service.State -cne 'Running') { throw 'The exact QuietShield service is not running.' }
$installedExecutable = [string]$owned.Manifest.executablePath
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path ([string]$owned.Manifest.installRoot) 'service-ipc-test.json' }
& $installedExecutable --ipc-smoke --pipe-name 'QuietShield.Service.v1' --output ([IO.Path]::GetFullPath($OutputPath))
if ($LASTEXITCODE -ne 0) { throw ('The installed service IPC test failed with exit code ' + [string]$LASTEXITCODE) }
$result = Get-Content -LiteralPath $OutputPath -Raw | ConvertFrom-Json
if ([string]$result.status -cne 'Passed') { throw 'The installed service IPC test did not report Passed.' }
[pscustomobject]@{ status = 'Passed'; serviceInstalled = $true; serviceRunning = $true; ipcConnected = $true; persistentEnforcementAvailable = [bool]$result.serviceStatus.persistentEnforcementAvailable; output = [IO.Path]::GetFullPath($OutputPath) } | ConvertTo-Json -Depth 5
