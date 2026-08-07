[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$ApprovedServiceInstallation,
    [Guid]$ApprovedRehearsalId = [Guid]::Empty,
    [string]$PackageRoot = '',
    [string]$InstallRoot = 'D:\QuietShield\Service',
    [string]$StateRoot = 'D:\QuietShield\State',
    [string]$ProbePath = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ServiceActivation.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'QuietShieldService.Install.Common.ps1')
Assert-QuietShieldPowerShell51
$root = Get-QuietShieldRepositoryRoot
if ([string]::IsNullOrWhiteSpace($PackageRoot)) { $PackageRoot = Join-Path $root 'artifacts\service-package\Release' }
if ([string]::IsNullOrWhiteSpace($ProbePath)) { $ProbePath = Join-Path $root 'artifacts\bin\QuietShield.ConnectionProbe\x64\Release\net10.0\QuietShield.ConnectionProbe.exe' }
$package = Test-QuietShieldServicePackage -PackageRoot $PackageRoot
$install = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
$state = [IO.Path]::GetFullPath($StateRoot).TrimEnd('\')
$probe = [IO.Path]::GetFullPath($ProbePath)
if (-not $install.StartsWith('D:\QuietShield\', [StringComparison]::OrdinalIgnoreCase) -or -not $state.StartsWith('D:\QuietShield\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Phase 10B service and state roots must remain under D:\QuietShield.' }
if (-not (Test-Path -LiteralPath $probe -PathType Leaf)) { throw 'The validated dedicated Release probe is missing.' }
$collision = Assert-QuietShieldNoForeignServiceCollision -InstallRoot $install
if ($null -ne $collision -and $null -ne $collision.Service) {
    [pscustomobject]@{ status = 'AlreadyInstalled'; serviceName = 'QuietShieldService'; exactOwnedService = $true; changed = $false } | ConvertTo-Json -Compress
    return
}
if ($ApprovedRehearsalId -eq [Guid]::Empty) { throw 'An explicit approved rehearsal ID is required.' }

$plan = [pscustomobject][ordered]@{
    status = 'InstallationPlanValidated'; serviceName = 'QuietShieldService'; displayName = 'QuietShield Protection Service';
    packagePayloadSha256 = $package.PayloadSha256; sourceExecutable = $package.ExecutablePath; installRoot = $install; stateRoot = $state;
    probePath = $probe; startup = 'AutomaticDelayedStart'; account = 'LocalSystem'; recovery = 'RestartAfter60SecondsThreeTimes';
    existingExactServiceCount = @(Get-QuietShieldExactService).Count; foreignServiceRefused = $true; modifyingCommandInvoked = $false
}
if ($WhatIfPreference) { $plan | ConvertTo-Json -Depth 6; return }
if (-not $ApprovedServiceInstallation) { throw 'Service installation requires -ApprovedServiceInstallation.' }
if (-not (Test-QuietShieldAdministrator)) { throw 'Service installation requires an already elevated Administrator console and never self-elevates.' }

$authorizedSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($null -ne $collision -and $null -eq $collision.Service -and $PSCmdlet.ShouldProcess($install, 'Remove exact validated orphaned service package before reinstall')) { Remove-Item -LiteralPath $install -Recurse -Force }
New-Item -ItemType Directory -Path $install -Force | Out-Null
foreach ($sourceFile in Get-ChildItem -LiteralPath $package.Root -File -Recurse) {
    $relative = $sourceFile.FullName.Substring($package.Root.Length + 1)
    $destination = Join-Path $install $relative
    $destinationDirectory = Split-Path -Parent $destination
    if (-not (Test-Path -LiteralPath $destinationDirectory)) { New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null }
    Copy-Item -LiteralPath $sourceFile.FullName -Destination $destination -Force
}
[void](Test-QuietShieldServicePackage -PackageRoot $install)
New-Item -ItemType Directory -Path $state -Force | Out-Null
$serviceExecutable = Join-Path $install 'QuietShield.Service.exe'
$enforcementScript = Join-Path $install 'scripts\Invoke-ServiceFirewallPolicy.ps1'
$activationPath = Join-Path $state 'activation-config.json'
$createdAt = [DateTimeOffset]::UtcNow
$activation = [pscustomobject][ordered]@{
    schemaVersion = 1; productMarker = 'QuietShield'; purpose = 'Phase10BControlledServiceRehearsal'; serviceName = 'QuietShieldService';
    approvedRehearsalId = $ApprovedRehearsalId.ToString('D'); authorizedUserSid = $authorizedSid; probePath = $probe;
    probeSha256 = Get-QuietShieldFileSha256 -Path $probe; enforcementScriptPath = $enforcementScript;
    enforcementScriptSha256 = Get-QuietShieldFileSha256 -Path $enforcementScript; createdAtUtc = $createdAt.ToString('O');
    expiresAtUtc = $createdAt.AddHours(2).ToString('O'); payloadSha256 = ''
}
$activation.payloadSha256 = Get-QuietShieldServiceActivationPayloadHash -Configuration $activation
$activation | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $activationPath -Encoding UTF8
[void](Test-QuietShieldServiceActivationConfiguration -Path $activationPath)
$binaryPath = '"' + $serviceExecutable + '" --service --pipe-name QuietShield.Service.v1 --state-root "' + $state + '" --activation-config "' + $activationPath + '"'
$ownership = [pscustomobject][ordered]@{
    schemaVersion = 1; productMarker = 'QuietShield'; purpose = 'QuietShieldServiceOwnership'; serviceName = 'QuietShieldService';
    displayName = 'QuietShield Protection Service'; installRoot = $install; executablePath = $serviceExecutable;
    executableSha256 = Get-QuietShieldFileSha256 -Path $serviceExecutable; activationConfigPath = $activationPath;
    activationConfigSha256 = Get-QuietShieldFileSha256 -Path $activationPath; binaryPathName = $binaryPath;
    authorizedUserSid = $authorizedSid; installedAtUtc = [DateTimeOffset]::UtcNow.ToString('O'); payloadSha256 = ''
}
$ownership.payloadSha256 = Get-QuietShieldServiceOwnershipPayloadHash -Manifest $ownership
$ownershipPath = Join-Path $install 'service-ownership.json'
$ownership | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ownershipPath -Encoding UTF8

& icacls.exe $install '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' ('*' + $authorizedSid + ':(OI)(CI)RX') | Out-Null
if ($LASTEXITCODE -ne 0) { throw ('Failed to secure exact QuietShield installation directory: ' + $install) }
& icacls.exe $state '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' ('*' + $authorizedSid + ':(OI)(CI)R') | Out-Null
if ($LASTEXITCODE -ne 0) { throw ('Failed to secure exact QuietShield state directory: ' + $state) }

$createdService = $false
try {
    if ($PSCmdlet.ShouldProcess('QuietShieldService', 'Create exact QuietShield Windows service')) {
        New-Service -Name 'QuietShieldService' -BinaryPathName $binaryPath -DisplayName 'QuietShield Protection Service' -Description 'QuietShield controlled persistent protection service.' -StartupType Automatic | Out-Null
        $createdService = $true
        & sc.exe config 'QuietShieldService' 'start=' 'delayed-auto' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Failed to configure automatic delayed start.' }
        & sc.exe failure 'QuietShieldService' 'reset=' '86400' 'actions=' 'restart/60000/restart/60000/restart/60000' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Failed to configure service failure recovery.' }
        & sc.exe failureflag 'QuietShieldService' '1' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Failed to configure non-crash failure recovery.' }
    }
    [void](Test-QuietShieldServiceOwnership -InstallRoot $install)
    [pscustomobject]@{ status = 'Installed'; serviceName = 'QuietShieldService'; displayName = 'QuietShield Protection Service'; automaticDelayedStart = $true; recoveryConfigured = $true; serviceStarted = $false; restartRequired = $false } | ConvertTo-Json -Compress
}
catch {
    if ($createdService) { & sc.exe delete 'QuietShieldService' | Out-Null }
    throw
}
