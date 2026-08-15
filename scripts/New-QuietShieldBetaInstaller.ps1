[CmdletBinding()]
param([string]$SignToolName = '')

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ServiceActivation.Script.Common.ps1')
Assert-QuietShieldPowerShell51
Assert-QuietShieldNonElevated
Initialize-QuietShieldProcessEnvironment
$repositoryRoot = Get-QuietShieldRepositoryRoot
$buildProperties = [xml](Get-Content -LiteralPath (Join-Path $repositoryRoot 'Directory.Build.props') -Raw)
$version = [string]$buildProperties.Project.PropertyGroup.QuietShieldVersion
if ($version -notmatch '\A\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\z') { throw 'Directory.Build.props does not contain a valid authoritative QuietShieldVersion.' }
$installerRoot = Join-Path $repositoryRoot 'installer'
. (Join-Path $installerRoot 'QuietShield.Installer.Common.ps1')
$artifactRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot ('artifacts\installer\' + $version)))
$allowedRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot 'artifacts\installer')).TrimEnd('\') + '\'
if (-not $artifactRoot.StartsWith($allowedRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'The installer artifact root escaped artifacts\installer.' }
if (Test-Path -LiteralPath $artifactRoot) { Remove-Item -LiteralPath $artifactRoot -Recurse -Force }
$payloadRoot = Join-Path $artifactRoot 'payload'
$appRoot = Join-Path $payloadRoot 'app'
$serviceRoot = Join-Path $payloadRoot 'service'
$installerPayloadRoot = Join-Path $payloadRoot 'installer'
$outputRoot = Join-Path $artifactRoot 'package'
foreach ($directory in @($appRoot, $serviceRoot, $installerPayloadRoot, $outputRoot)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }

$commonPublishArguments = @('-c','Release','-r','win-x64','--self-contained','true','-p:PublishSingleFile=false','-p:PublishTrimmed=false','-p:PublishReadyToRun=false','-p:DebugType=None','-p:DebugSymbols=false','-p:GenerateDocumentationFile=false')
Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList (@('publish',(Join-Path $repositoryRoot 'src\QuietShield.App\QuietShield.App.csproj')) + $commonPublishArguments + @('-o',$appRoot))
Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList (@('publish',(Join-Path $repositoryRoot 'src\QuietShield.Service\QuietShield.Service.csproj')) + $commonPublishArguments + @('-o',$serviceRoot))
$developmentSettings = Join-Path $serviceRoot 'appsettings.Development.json'
if (Test-Path -LiteralPath $developmentSettings) { Remove-Item -LiteralPath $developmentSettings -Force }

$serviceScriptsRoot = Join-Path $serviceRoot 'scripts'
New-Item -ItemType Directory -Path $serviceScriptsRoot -Force | Out-Null
foreach ($name in @('QuietShield.Script.Common.ps1','ServiceActivation.Script.Common.ps1','Invoke-ServiceFirewallPolicy.ps1')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $serviceScriptsRoot $name)
}
foreach ($name in @('QuietShield.Installer.Common.ps1','Install-QuietShieldProductionService.ps1','Uninstall-QuietShieldProductionService.ps1','Prepare-QuietShieldProductionUpgrade.ps1')) {
    Copy-Item -LiteralPath (Join-Path $installerRoot $name) -Destination (Join-Path $installerPayloadRoot $name)
}
Copy-Item -LiteralPath (Join-Path $installerRoot 'phase12-security-policy.json') -Destination (Join-Path $installerPayloadRoot 'phase12-security-policy.json')
foreach ($name in @('QuietShield.Script.Common.ps1','ServiceActivation.Script.Common.ps1','Invoke-ServiceFirewallPolicy.ps1','Restore-QuietShieldServiceState.ps1')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $installerPayloadRoot $name)
}

function New-ComponentManifest {
    param([Parameter(Mandatory = $true)][string]$ComponentRoot, [Parameter(Mandatory = $true)][string]$Component)
    $files = @(Get-ChildItem -LiteralPath $ComponentRoot -File -Recurse | Sort-Object -Property FullName | ForEach-Object {
        [pscustomobject][ordered]@{ relativePath = $_.FullName.Substring($ComponentRoot.Length + 1).Replace('\','/'); sha256 = Get-QuietShieldFileSha256 -Path $_.FullName; length = [long]$_.Length }
    })
    $manifest = [pscustomobject][ordered]@{ schemaVersion = 1; productMarker = 'QuietShield'; purpose = 'SelfContainedInstallerComponent'; component = $Component; version = $version; runtimeIdentifier = 'win-x64'; selfContained = $true; files = $files; payloadSha256 = '' }
    $manifest.payloadSha256 = Get-QuietShieldComponentManifestPayloadHash -Manifest $manifest
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ComponentRoot 'quietshield-component-manifest.json') -Encoding UTF8
    return $manifest
}

$appManifest = New-ComponentManifest -ComponentRoot $appRoot -Component 'QuietShield.App'
$serviceManifest = New-ComponentManifest -ComponentRoot $serviceRoot -Component 'QuietShield.Service'
$sourceCommit = (& git -C $repositoryRoot rev-parse HEAD | Select-Object -First 1).Trim()
$payloadManifest = [pscustomobject][ordered]@{
    schemaVersion = 1; productMarker = 'QuietShield'; purpose = 'QuietShieldBetaInstallerPayload'; version = $version; architecture = 'x64'; runtimeIdentifier = 'win-x64'; selfContained = $true
    upgradeAppId = $script:QuietShieldInstallerAppId; sourceCommit = $sourceCommit; appPayloadSha256 = $appManifest.payloadSha256; servicePayloadSha256 = $serviceManifest.payloadSha256
    productionProductRoot = '{autopf}\QuietShield'; productionStateRoot = '{commonappdata}\QuietShield\Service'; serviceName = 'QuietShieldService'
    dnsActivationIncluded = $false; createsProgramLockRulesDuringInstall = $false; signingRequiredForRelease = $true; signingApplied = -not [string]::IsNullOrWhiteSpace($SignToolName)
}
$payloadManifestPath = Join-Path $installerPayloadRoot 'phase12-installer-payload-manifest.json'
$payloadManifest | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $payloadManifestPath -Encoding UTF8

$iscc = 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe'
if (-not (Test-Path -LiteralPath $iscc -PathType Leaf)) { throw 'The validated Inno Setup 6 compiler is unavailable.' }
$compilerArguments = @('/Qp',('/DAppVersion=' + $version),('/DSourceRoot=' + $payloadRoot),('/DOutputDir=' + $outputRoot))
if (-not [string]::IsNullOrWhiteSpace($SignToolName)) { $compilerArguments += ('/DQuietShieldSignTool=' + $SignToolName) }
$compilerArguments += (Join-Path $installerRoot 'QuietShield.iss')
Invoke-QuietShieldCommand -FilePath $iscc -ArgumentList $compilerArguments
$installerPath = Join-Path $outputRoot ('QuietShield-Windows-x64-' + $version + '.exe')
if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf)) { throw 'Inno Setup did not produce the expected versioned installer.' }
$signature = Get-AuthenticodeSignature -LiteralPath $installerPath
$inventory = @(Get-ChildItem -LiteralPath $artifactRoot -File -Recurse | Sort-Object -Property FullName | ForEach-Object {
    [pscustomobject][ordered]@{ relativePath = $_.FullName.Substring($artifactRoot.Length + 1).Replace('\','/'); sha256 = Get-QuietShieldFileSha256 -Path $_.FullName; length = [long]$_.Length }
})
$packageManifest = [pscustomobject][ordered]@{
    schemaVersion = 1; productMarker = 'QuietShield'; purpose = 'QuietShieldBetaInstallerPackage'; version = $version; architecture = 'x64'; selfContained = $true; sourceCommit = $sourceCommit
    installerRelativePath = $installerPath.Substring($artifactRoot.Length + 1).Replace('\','/'); installerSha256 = Get-QuietShieldFileSha256 -Path $installerPath; installerLength = [long](Get-Item -LiteralPath $installerPath).Length
    signingStatus = [string]$signature.Status; signingApplied = [string]$signature.Status -ceq 'Valid'; signingRequiredForRelease = $true
    inventory = $inventory
}
$packageManifestPath = Join-Path $artifactRoot 'phase12-package-manifest.json'
$packageManifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $packageManifestPath -Encoding UTF8
& (Join-Path $PSScriptRoot 'Test-QuietShieldBetaInstaller.ps1') -ArtifactRoot $artifactRoot
