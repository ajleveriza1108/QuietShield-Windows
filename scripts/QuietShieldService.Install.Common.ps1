Set-StrictMode -Version 2.0

function Get-QuietShieldServiceLifecycleDisposition {
    [CmdletBinding()]
    param(
        [ValidateRange(0, 2)][int]$ServiceCount,
        [bool]$OwnershipManifestPresent,
        [bool]$ExactIdentityValid,
        [ValidateSet('Install','Uninstall')][string]$Operation
    )
    if ($ServiceCount -gt 1) { return 'RefuseAmbiguousServiceIdentity' }
    if ($ServiceCount -eq 1 -and (-not $OwnershipManifestPresent -or -not $ExactIdentityValid)) { return 'RefuseForeignService' }
    if ($Operation -eq 'Install') {
        if ($ServiceCount -eq 1) { return 'AlreadyInstalled' }
        if ($OwnershipManifestPresent -and $ExactIdentityValid) { return 'ResumeValidatedOrphan' }
        return 'FreshInstall'
    }
    if ($ServiceCount -eq 0 -and -not $OwnershipManifestPresent) { return 'AlreadyUninstalled' }
    if ($ExactIdentityValid) { return 'UninstallExactOwnedServiceOnly' }
    return 'RefuseForeignService'
}

function Get-QuietShieldServiceOwnershipPayloadHash {
    param([Parameter(Mandatory = $true)]$Manifest)
    $canonical = @([string][int]$Manifest.schemaVersion, [string]$Manifest.productMarker, [string]$Manifest.purpose,
        [string]$Manifest.serviceName, [string]$Manifest.displayName, [IO.Path]::GetFullPath([string]$Manifest.installRoot),
        [IO.Path]::GetFullPath([string]$Manifest.executablePath), ([string]$Manifest.executableSha256).ToUpperInvariant(),
        [IO.Path]::GetFullPath([string]$Manifest.activationConfigPath), ([string]$Manifest.activationConfigSha256).ToUpperInvariant(),
        [string]$Manifest.binaryPathName, [string]$Manifest.authorizedUserSid, ([DateTimeOffset]$Manifest.installedAtUtc).ToUniversalTime().ToString('O')) -join '|'
    return Get-QuietShieldUtf8Sha256 -Value $canonical
}

function Test-QuietShieldServiceOwnership {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$InstallRoot, [switch]$AllowAbsentService)
    $resolvedRoot = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
    $manifestPath = Join-Path $resolvedRoot 'service-ownership.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'The exact QuietShield service ownership manifest is missing.' }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ([int]$manifest.schemaVersion -ne 1 -or [string]$manifest.productMarker -cne 'QuietShield' -or [string]$manifest.purpose -cne 'QuietShieldServiceOwnership' -or
        [string]$manifest.serviceName -cne 'QuietShieldService' -or [string]$manifest.displayName -cne 'QuietShield Protection Service' -or [IO.Path]::GetFullPath([string]$manifest.installRoot).TrimEnd('\') -cne $resolvedRoot) { throw 'The service ownership manifest identity is invalid.' }
    foreach ($pair in @(@([string]$manifest.executablePath,[string]$manifest.executableSha256), @([string]$manifest.activationConfigPath,[string]$manifest.activationConfigSha256))) {
        if (-not (Test-Path -LiteralPath $pair[0] -PathType Leaf) -or (Get-QuietShieldFileSha256 -Path $pair[0]) -cne $pair[1].ToUpperInvariant()) { throw 'An exact owned service file failed hash validation.' }
    }
    if ((Get-QuietShieldServiceOwnershipPayloadHash -Manifest $manifest) -cne ([string]$manifest.payloadSha256).ToUpperInvariant()) { throw 'The service ownership payload hash is invalid.' }
    $services = @(Get-QuietShieldExactService)
    if ($services.Count -gt 1) { throw 'The exact service identity is ambiguous.' }
    if (-not $AllowAbsentService -and $services.Count -ne 1) { throw 'The exact QuietShield service is absent.' }
    if ($services.Count -eq 1 -and ([string]$services[0].DisplayName -cne [string]$manifest.displayName -or [string]$services[0].PathName -cne [string]$manifest.binaryPathName)) { throw 'A foreign or incorrectly configured service uses the QuietShield service name.' }
    $service = $null
    if ($services.Count -eq 1) { $service = $services[0] }
    return [pscustomobject]@{ Manifest = $manifest; ManifestPath = $manifestPath; Service = $service }
}

function Assert-QuietShieldNoForeignServiceCollision {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)
    $services = @(Get-QuietShieldExactService)
    if ($services.Count -gt 1) { throw 'The exact service identity is ambiguous.' }
    if ($services.Count -eq 1) { return Test-QuietShieldServiceOwnership -InstallRoot $InstallRoot }
    $manifestPath = Join-Path ([IO.Path]::GetFullPath($InstallRoot)) 'service-ownership.json'
    if (Test-Path -LiteralPath $manifestPath -PathType Leaf) { return Test-QuietShieldServiceOwnership -InstallRoot $InstallRoot -AllowAbsentService }
    return $null
}
