[CmdletBinding()]
param([string]$ArtifactRoot = '', [switch]$SourceOnly)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ServiceActivation.Script.Common.ps1')
Assert-QuietShieldPowerShell51
$repositoryRoot = Get-QuietShieldRepositoryRoot
$installerSourceRoot = Join-Path $repositoryRoot 'installer'
. (Join-Path $installerSourceRoot 'QuietShield.Installer.Common.ps1')
$buildProperties = [xml](Get-Content -LiteralPath (Join-Path $repositoryRoot 'Directory.Build.props') -Raw)
$version = [string]$buildProperties.Project.PropertyGroup.QuietShieldVersion
if ($version -notmatch '\A\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\z') { throw 'The authoritative QuietShieldVersion is invalid.' }

$scriptsToParse = @(
    (Join-Path $installerSourceRoot 'QuietShield.Installer.Common.ps1'),
    (Join-Path $installerSourceRoot 'Install-QuietShieldProductionService.ps1'),
    (Join-Path $installerSourceRoot 'Prepare-QuietShieldProductionUpgrade.ps1'),
    (Join-Path $installerSourceRoot 'Uninstall-QuietShieldProductionService.ps1'),
    (Join-Path $PSScriptRoot 'New-QuietShieldBetaInstaller.ps1'),
    (Join-Path $PSScriptRoot 'Test-QuietShieldBetaInstaller.ps1'),
    (Join-Path $PSScriptRoot 'ServiceActivation.Script.Common.ps1'),
    (Join-Path $PSScriptRoot 'Restore-QuietShieldServiceState.ps1')
)
foreach ($scriptPath in $scriptsToParse) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
    if (@($errors).Count -ne 0) { throw ('PowerShell 5.1 parsing failed for ' + $scriptPath + ': ' + (@($errors | ForEach-Object { $_.Message }) -join ' | ')) }
}

$appProject = Get-Content -LiteralPath (Join-Path $repositoryRoot 'src\QuietShield.App\QuietShield.App.csproj') -Raw
$viewModel = Get-Content -LiteralPath (Join-Path $repositoryRoot 'src\QuietShield.App\ViewModels\Phase2MainViewModel.cs') -Raw
if ($appProject -match '<Version>|<AssemblyInformationalVersion>') { throw 'The App project duplicates the authoritative repository version.' }
if ($viewModel.IndexOf('AssemblyInformationalVersionAttribute', [StringComparison]::Ordinal) -lt 0) { throw 'The desktop version display does not use the authoritative assembly version.' }
$appManifest = Get-Content -LiteralPath (Join-Path $repositoryRoot 'src\QuietShield.App\app.manifest') -Raw
if ($appManifest.IndexOf('requestedExecutionLevel level="asInvoker"', [StringComparison]::Ordinal) -lt 0) { throw 'The desktop application must remain asInvoker.' }

$iss = Get-Content -LiteralPath (Join-Path $installerSourceRoot 'QuietShield.iss') -Raw
$securityPolicy = Get-Content -LiteralPath (Join-Path $installerSourceRoot 'phase12-security-policy.json') -Raw | ConvertFrom-Json
if ([int]$securityPolicy.schemaVersion -ne 1 -or [string]$securityPolicy.productMarker -cne 'QuietShield' -or
    [string]$securityPolicy.purpose -cne 'Phase12InstallerStaticSecurityPolicy' -or @($securityPolicy.installerForbiddenFragments).Count -lt 5 -or
    @($securityPolicy.lifecycleForbiddenFragments).Count -lt 5) { throw 'The Phase 12 static security policy is invalid or incomplete.' }
foreach ($required in @('PrivilegesRequired=admin','ArchitecturesAllowed=x64compatible','ArchitecturesInstallIn64BitMode=x64compatible','SignedUninstaller','ProductAppId','RunProductionServiceInstall','RunProductionServiceUninstall','RestartIfNeededByRun=no')) {
    if ($iss.IndexOf($required, [StringComparison]::Ordinal) -lt 0) { throw ('The Inno Setup source is missing: ' + $required) }
}
foreach ($forbidden in @($securityPolicy.installerForbiddenFragments)) {
    if ($iss.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) { throw ('The installer source contains a prohibited operation: ' + $forbidden) }
}
$installSource = Get-Content -LiteralPath (Join-Path $installerSourceRoot 'Install-QuietShieldProductionService.ps1') -Raw
$uninstallSource = Get-Content -LiteralPath (Join-Path $installerSourceRoot 'Uninstall-QuietShieldProductionService.ps1') -Raw
foreach ($forbidden in @($securityPolicy.lifecycleForbiddenFragments)) {
    if ($installSource.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or $uninstallSource.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw ('A lifecycle script contains a prohibited direct system operation: ' + $forbidden)
    }
}
foreach ($required in @('Test-QuietShieldProductionOwnership','Get-CimInstance -ClassName Win32_Service -Filter "Name=''QuietShieldService''"','CleanupForUninstall','broadFirewallCleanup = $false')) {
    if (($installSource + $uninstallSource).IndexOf($required, [StringComparison]::Ordinal) -lt 0) { throw ('Exact lifecycle ownership validation is missing: ' + $required) }
}
$layout = Get-QuietShieldProductionLayout -Version $version -ProgramFilesRoot 'D:\Program Files' -CommonApplicationDataRoot 'D:\ProgramData'
if ([string]$layout.ProductRoot -cne 'D:\Program Files\QuietShield' -or [string]$layout.StateRoot -cne 'D:\ProgramData\QuietShield\Service') { throw 'Production path generation is not deterministic.' }
$serviceCommand = Get-QuietShieldProductionServiceCommandLine -Layout $layout
if ($serviceCommand.IndexOf('--production-config', [StringComparison]::Ordinal) -lt 0 -or $serviceCommand.IndexOf('--activation-config', [StringComparison]::Ordinal) -ge 0) { throw 'The production service registration command is invalid.' }

$sourceResult = [ordered]@{
    status = 'Passed'; version = $version; powershell51Parsed = $scriptsToParse.Count; installerTechnology = 'Inno Setup 6'; productionPaths = 'Passed'
    serviceRegistrationGeneration = 'Passed'; uninstallOwnershipBoundaries = 'Passed'; dnsActivationAbsent = $true; installFirewallRuleCreationAbsent = $true
    silentSelfElevationAbsent = $true; upgradeIdentity = $script:QuietShieldInstallerAppId; networkSpecificPersistenceGated = $true
}
if ($SourceOnly) { [pscustomobject]$sourceResult | ConvertTo-Json -Depth 6; return }
if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) { $ArtifactRoot = Join-Path $repositoryRoot ('artifacts\installer\' + $version) }
$resolvedArtifactRoot = [IO.Path]::GetFullPath($ArtifactRoot).TrimEnd('\')
$allowedArtifactRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot 'artifacts\installer')).TrimEnd('\') + '\'
if (-not $resolvedArtifactRoot.StartsWith($allowedArtifactRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Artifact validation is restricted to artifacts\installer.' }
$packageManifestPath = Join-Path $resolvedArtifactRoot 'phase12-package-manifest.json'
if (-not (Test-Path -LiteralPath $packageManifestPath -PathType Leaf)) { throw 'The Phase 12 package manifest is missing.' }
$packageManifest = Get-Content -LiteralPath $packageManifestPath -Raw | ConvertFrom-Json
if ([int]$packageManifest.schemaVersion -ne 1 -or [string]$packageManifest.productMarker -cne 'QuietShield' -or [string]$packageManifest.purpose -cne 'QuietShieldBetaInstallerPackage' -or
    [string]$packageManifest.version -cne $version -or [string]$packageManifest.architecture -cne 'x64' -or -not [bool]$packageManifest.selfContained) { throw 'The Phase 12 package manifest identity is invalid.' }
$appRoot = Join-Path $resolvedArtifactRoot 'payload\app'
$serviceRoot = Join-Path $resolvedArtifactRoot 'payload\service'
[void](Test-QuietShieldComponentManifest -ComponentRoot $appRoot -ExpectedComponent 'QuietShield.App' -ExpectedVersion $version)
[void](Test-QuietShieldComponentManifest -ComponentRoot $serviceRoot -ExpectedComponent 'QuietShield.Service' -ExpectedVersion $version)
foreach ($requiredPath in @(
    (Join-Path $appRoot 'QuietShield.App.exe'), (Join-Path $appRoot 'coreclr.dll'), (Join-Path $appRoot 'hostfxr.dll'), (Join-Path $appRoot 'PresentationFramework.dll'),
    (Join-Path $serviceRoot 'QuietShield.Service.exe'), (Join-Path $serviceRoot 'coreclr.dll'), (Join-Path $serviceRoot 'hostfxr.dll'),
    (Join-Path $serviceRoot 'scripts\Invoke-ServiceFirewallPolicy.ps1'))) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) { throw ('A required self-contained file is missing: ' + $requiredPath) }
}
$forbiddenArtifacts = @(Get-ChildItem -LiteralPath (Join-Path $resolvedArtifactRoot 'payload') -File -Recurse | Where-Object {
    $_.Extension -in @('.pdb','.dbg','.user','.suo','.pfx','.p12','.key','.snk') -or $_.Name -match '(?i)(testhost|\.Tests\.|appsettings\.Development|QuietShield\.(DnsHost|DnsWatchdog|ConnectionProbe)\.exe)'
})
if ($forbiddenArtifacts.Count -ne 0) { throw ('Developer, test, private, or excluded runtime artifacts were packaged: ' + (@($forbiddenArtifacts.FullName) -join ', ')) }
foreach ($binary in @((Join-Path $appRoot 'QuietShield.App.exe'),(Join-Path $serviceRoot 'QuietShield.Service.exe'))) {
    if (-not ([string](Get-Item -LiteralPath $binary).VersionInfo.ProductVersion).StartsWith($version, [StringComparison]::OrdinalIgnoreCase)) { throw ('A published binary version is inconsistent: ' + $binary) }
}
$installerPath = Join-Path $resolvedArtifactRoot ([string]$packageManifest.installerRelativePath)
if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf) -or (Get-QuietShieldFileSha256 -Path $installerPath) -cne ([string]$packageManifest.installerSha256).ToUpperInvariant() -or
    (Get-Item -LiteralPath $installerPath).Length -ne [long]$packageManifest.installerLength) { throw 'The compiled installer failed package-manifest validation.' }
$actualInventory = @(Get-ChildItem -LiteralPath $resolvedArtifactRoot -File -Recurse | Where-Object { $_.FullName -cne $packageManifestPath -and $_.Name -cne 'phase12-validation.json' } |
    ForEach-Object { $_.FullName.Substring($resolvedArtifactRoot.Length + 1).Replace('\','/') } | Sort-Object)
$expectedInventory = @($packageManifest.inventory | ForEach-Object { [string]$_.relativePath } | Sort-Object)
if (($actualInventory -join '|') -cne ($expectedInventory -join '|')) { throw 'The package file inventory contains missing or unexpected files.' }
foreach ($entry in @($packageManifest.inventory)) {
    $path = Join-Path $resolvedArtifactRoot ([string]$entry.relativePath)
    if ((Get-QuietShieldFileSha256 -Path $path) -cne ([string]$entry.sha256).ToUpperInvariant() -or (Get-Item -LiteralPath $path).Length -ne [long]$entry.length) { throw ('Package inventory validation failed: ' + [string]$entry.relativePath) }
}
$signature = Get-AuthenticodeSignature -LiteralPath $installerPath
$result = [pscustomobject][ordered]@{
    status = 'Passed'; version = $version; installerTechnology = 'Inno Setup 6'; artifactRoot = $resolvedArtifactRoot; installerPath = $installerPath
    installerSha256 = [string]$packageManifest.installerSha256; selfContained = $true; architecture = 'x64'; appFiles = @((Get-ChildItem -LiteralPath $appRoot -File -Recurse)).Count
    serviceFiles = @((Get-ChildItem -LiteralPath $serviceRoot -File -Recurse)).Count; packageInventoryFiles = @($packageManifest.inventory).Count
    powershell51Parsed = $scriptsToParse.Count; sourceValidation = $sourceResult; signingStatus = [string]$signature.Status; signingRequiredForRelease = $true
    systemChanges = 'None'; realInstallTest = 'NotYetAttempted'
}
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $resolvedArtifactRoot 'phase12-validation.json') -Encoding UTF8
$result | ConvertTo-Json -Depth 8
