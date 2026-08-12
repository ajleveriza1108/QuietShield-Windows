Set-StrictMode -Version 2.0

$script:QuietShieldInstallerAppId = '{6D13D40D-0A66-49F7-A422-235A2B89DA61}'
$script:QuietShieldProductionServiceName = 'QuietShieldService'
$script:QuietShieldProductionServiceDisplayName = 'QuietShield Protection Service'

function Get-QuietShieldProductionLayout {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Version,
        [string]$ProgramFilesRoot = ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)),
        [string]$CommonApplicationDataRoot = ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData))
    )
    if ($Version -notmatch '\A\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\z') { throw 'The package version is invalid.' }
    $productRoot = [IO.Path]::GetFullPath((Join-Path $ProgramFilesRoot 'QuietShield')).TrimEnd('\')
    $stateRoot = [IO.Path]::GetFullPath((Join-Path $CommonApplicationDataRoot 'QuietShield\Service')).TrimEnd('\')
    return [pscustomobject][ordered]@{
        ProductRoot = $productRoot
        AppRoot = Join-Path $productRoot ('App\' + $Version)
        ServiceRoot = Join-Path $productRoot ('Service\' + $Version)
        InstallerRoot = Join-Path $productRoot 'Installer'
        StateRoot = $stateRoot
        ProductionConfigurationPath = Join-Path $stateRoot 'production-config.json'
        ServiceOwnershipPath = Join-Path $stateRoot 'service-ownership.json'
    }
}

function Get-QuietShieldProductionServiceCommandLine {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Layout)
    $executable = Join-Path ([string]$Layout.ServiceRoot) 'QuietShield.Service.exe'
    return ('"{0}" --service --pipe-name QuietShield.Service.v1 --state-root "{1}" --production-config "{2}"' -f
        $executable, [string]$Layout.StateRoot, [string]$Layout.ProductionConfigurationPath)
}

function Get-QuietShieldComponentManifestPayloadHash {
    param([Parameter(Mandatory = $true)]$Manifest)
    $lines = @($Manifest.files | Sort-Object -Property relativePath | ForEach-Object {
        ([string]$_.relativePath) + '|' + ([string]$_.sha256).ToUpperInvariant() + '|' + [string][long]$_.length
    })
    $canonical = @([string][int]$Manifest.schemaVersion, [string]$Manifest.productMarker, [string]$Manifest.purpose,
        [string]$Manifest.component, [string]$Manifest.version, [string]$Manifest.runtimeIdentifier,
        ([bool]$Manifest.selfContained).ToString(), ($lines -join "`n")) -join '|'
    return Get-QuietShieldUtf8Sha256 -Value $canonical
}

function Test-QuietShieldComponentManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ComponentRoot, [Parameter(Mandatory = $true)][string]$ExpectedComponent, [Parameter(Mandatory = $true)][string]$ExpectedVersion)
    $resolvedRoot = [IO.Path]::GetFullPath($ComponentRoot).TrimEnd('\')
    $manifestPath = Join-Path $resolvedRoot 'quietshield-component-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'The component manifest is missing.' }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ([int]$manifest.schemaVersion -ne 1 -or [string]$manifest.productMarker -cne 'QuietShield' -or
        [string]$manifest.purpose -cne 'SelfContainedInstallerComponent' -or [string]$manifest.component -cne $ExpectedComponent -or
        [string]$manifest.version -cne $ExpectedVersion -or [string]$manifest.runtimeIdentifier -cne 'win-x64' -or -not [bool]$manifest.selfContained) {
        throw 'The component manifest identity is invalid.'
    }
    $entries = @($manifest.files)
    if ($entries.Count -eq 0) { throw 'The component manifest has no files.' }
    foreach ($entry in $entries) {
        $relative = [string]$entry.relativePath
        if ([string]::IsNullOrWhiteSpace($relative) -or [IO.Path]::IsPathRooted($relative) -or $relative.Contains('..')) { throw 'The component manifest contains an unsafe path.' }
        $path = Join-Path $resolvedRoot $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-QuietShieldFileSha256 -Path $path) -cne ([string]$entry.sha256).ToUpperInvariant() -or
            (Get-Item -LiteralPath $path).Length -ne [long]$entry.length) { throw ('A component file failed validation: ' + $relative) }
    }
    $actual = @(Get-ChildItem -LiteralPath $resolvedRoot -File -Recurse | Where-Object { $_.FullName -cne $manifestPath } |
        ForEach-Object { $_.FullName.Substring($resolvedRoot.Length + 1).Replace('\','/') } | Sort-Object)
    $expected = @($entries | ForEach-Object { ([string]$_.relativePath).Replace('\','/') } | Sort-Object)
    if (($actual -join '|') -cne ($expected -join '|')) { throw 'The component payload contains missing or unexpected files.' }
    $payloadHash = Get-QuietShieldComponentManifestPayloadHash -Manifest $manifest
    if ($payloadHash -cne ([string]$manifest.payloadSha256).ToUpperInvariant()) { throw 'The component manifest payload hash is invalid.' }
    return [pscustomobject]@{ Root = $resolvedRoot; Manifest = $manifest; PayloadSha256 = $payloadHash }
}

function Get-QuietShieldProductionOwnershipPayloadHash {
    param([Parameter(Mandatory = $true)]$Manifest)
    $canonical = @([string][int]$Manifest.schemaVersion, [string]$Manifest.productMarker, [string]$Manifest.purpose,
        [string]$Manifest.installerAppId, [string]$Manifest.version, [string]$Manifest.serviceName, [string]$Manifest.displayName,
        [IO.Path]::GetFullPath([string]$Manifest.productRoot), [IO.Path]::GetFullPath([string]$Manifest.serviceRoot),
        [IO.Path]::GetFullPath([string]$Manifest.executablePath), ([string]$Manifest.executableSha256).ToUpperInvariant(),
        [IO.Path]::GetFullPath([string]$Manifest.configurationPath), ([string]$Manifest.configurationSha256).ToUpperInvariant(),
        [string]$Manifest.binaryPathName, [string]$Manifest.authorizedUserSid, ([Guid][string]$Manifest.installationId).ToString('D'),
        ([DateTimeOffset]$Manifest.installedAtUtc).ToUniversalTime().ToString('O')) -join '|'
    return Get-QuietShieldUtf8Sha256 -Value $canonical
}

function Test-QuietShieldProductionOwnership {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$OwnershipPath, [switch]$AllowAbsentService)
    $resolved = [IO.Path]::GetFullPath($OwnershipPath)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw 'The exact production service ownership manifest is missing.' }
    $manifest = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
    if ([int]$manifest.schemaVersion -ne 1 -or [string]$manifest.productMarker -cne 'QuietShield' -or
        [string]$manifest.purpose -cne 'QuietShieldProductionServiceOwnership' -or [string]$manifest.installerAppId -cne $script:QuietShieldInstallerAppId -or
        [string]$manifest.serviceName -cne $script:QuietShieldProductionServiceName -or [string]$manifest.displayName -cne $script:QuietShieldProductionServiceDisplayName) {
        throw 'The production service ownership identity is invalid.'
    }
    foreach ($pair in @(@([string]$manifest.executablePath,[string]$manifest.executableSha256), @([string]$manifest.configurationPath,[string]$manifest.configurationSha256))) {
        if (-not (Test-Path -LiteralPath $pair[0] -PathType Leaf) -or (Get-QuietShieldFileSha256 -Path $pair[0]) -cne ([string]$pair[1]).ToUpperInvariant()) {
            throw 'An exact owned production service file failed hash validation.'
        }
    }
    if ((Get-QuietShieldProductionOwnershipPayloadHash -Manifest $manifest) -cne ([string]$manifest.payloadSha256).ToUpperInvariant()) { throw 'The production service ownership payload hash is invalid.' }
    $services = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='QuietShieldService'" -ErrorAction SilentlyContinue)
    if ($services.Count -gt 1) { throw 'The exact production service identity is ambiguous.' }
    if (-not $AllowAbsentService -and $services.Count -ne 1) { throw 'The exact production service is absent.' }
    if ($services.Count -eq 1 -and ([string]$services[0].DisplayName -cne [string]$manifest.displayName -or [string]$services[0].PathName -cne [string]$manifest.binaryPathName)) {
        throw 'A foreign or incorrectly configured service uses the QuietShield service name.'
    }
    $service = $null
    if ($services.Count -eq 1) { $service = $services[0] }
    return [pscustomobject]@{ Path = $resolved; Manifest = $manifest; Service = $service }
}
