[CmdletBinding()]
param([string]$OutputPath = '')

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ServiceActivation.Script.Common.ps1')
Assert-QuietShieldPowerShell51
Assert-QuietShieldNonElevated
Initialize-QuietShieldProcessEnvironment
$root = Get-QuietShieldRepositoryRoot
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $root 'artifacts\service-package\Release' }
$output = [IO.Path]::GetFullPath($OutputPath).TrimEnd('\')
$allowedParent = [IO.Path]::GetFullPath((Join-Path $root 'artifacts\service-package')).TrimEnd('\') + '\'
if (-not $output.StartsWith($allowedParent, [StringComparison]::OrdinalIgnoreCase)) { throw 'The service package output must remain under artifacts\service-package.' }
if (Test-Path -LiteralPath $output) { Remove-Item -LiteralPath $output -Recurse -Force }
New-Item -ItemType Directory -Path $output -Force | Out-Null
Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @('publish', (Join-Path $root 'src\QuietShield.Service\QuietShield.Service.csproj'), '-c', 'Release', '--self-contained', 'false', '--no-restore', '-o', $output)
$scriptOutput = Join-Path $output 'scripts'
New-Item -ItemType Directory -Path $scriptOutput -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1') -Destination $scriptOutput
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'ServiceActivation.Script.Common.ps1') -Destination $scriptOutput
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Invoke-ServiceFirewallPolicy.ps1') -Destination $scriptOutput
$files = @(Get-ChildItem -LiteralPath $output -File -Recurse | Sort-Object -Property FullName | ForEach-Object {
    [pscustomobject][ordered]@{ relativePath = $_.FullName.Substring($output.Length + 1).Replace('\','/'); sha256 = Get-QuietShieldFileSha256 -Path $_.FullName; length = [long]$_.Length }
})
$manifest = [pscustomobject][ordered]@{ schemaVersion = 1; productMarker = 'QuietShield'; purpose = 'QuietShieldServicePackage'; serviceName = 'QuietShieldService'; createdAtUtc = [DateTimeOffset]::UtcNow.ToString('O'); files = $files; payloadSha256 = '' }
$manifest.payloadSha256 = Get-QuietShieldServicePackagePayloadHash -Manifest $manifest
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $output 'service-package-manifest.json') -Encoding UTF8
$validated = Test-QuietShieldServicePackage -PackageRoot $output
[pscustomobject]@{ status = 'PackageValidated'; packageRoot = $validated.Root; payloadSha256 = $validated.PayloadSha256; fileCount = $files.Count; executable = $validated.ExecutablePath } | ConvertTo-Json -Depth 5
