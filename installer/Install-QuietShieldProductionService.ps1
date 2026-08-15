[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$ApprovedInstallerServiceRegistration,
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$ProductRoot,
    [Parameter(Mandatory = $true)][string]$StateRoot,
    [string]$AuthorizedUserSid = '',
    [string]$AuthorizedUserProgramsRoot = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$sharedRoot = $PSScriptRoot
if (-not (Test-Path -LiteralPath (Join-Path $sharedRoot 'QuietShield.Script.Common.ps1') -PathType Leaf)) { $sharedRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\scripts')) }
. (Join-Path $sharedRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $sharedRoot 'ServiceActivation.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'QuietShield.Installer.Common.ps1')
Assert-QuietShieldPowerShell51

# R4.2.20 interactive installer identity
# Administrative Setup may run under credentials different from the logged-in desktop user.
# Resolve the interactive account explicitly and fail closed if it cannot be mapped to one profile.
function Resolve-QuietShieldInteractiveInstallIdentity {
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $accountName = [string]$computer.UserName
    if ([string]::IsNullOrWhiteSpace($accountName)) { throw 'No interactive Windows user is available for QuietShield authorization.' }
    try {
        $account = New-Object Security.Principal.NTAccount($accountName)
        $sid = [string]$account.Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch { throw ('The interactive Windows account could not be translated to a SID: ' + $accountName) }
    if ($sid -notmatch '\AS-1-') { throw 'The interactive Windows SID is invalid.' }
    $profileKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $sid
    $profile = Get-ItemProperty -LiteralPath $profileKey -Name ProfileImagePath -ErrorAction Stop
    $profilePath = [Environment]::ExpandEnvironmentVariables([string]$profile.ProfileImagePath).TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($profilePath) -or -not [IO.Path]::IsPathRooted($profilePath)) { throw 'The interactive Windows profile path is invalid.' }
    [pscustomobject]@{ Sid = $sid; ProgramsRoot = (Join-Path $profilePath 'AppData\Local\Programs') }
}
if ([string]::IsNullOrWhiteSpace($AuthorizedUserSid) -or [string]::IsNullOrWhiteSpace($AuthorizedUserProgramsRoot)) {
    $interactiveIdentity = Resolve-QuietShieldInteractiveInstallIdentity
    if (-not [string]::IsNullOrWhiteSpace($AuthorizedUserSid) -and -not $AuthorizedUserSid.Equals([string]$interactiveIdentity.Sid, [StringComparison]::OrdinalIgnoreCase)) { throw 'Provided authorized SID does not match the interactive Windows user.' }
    if (-not [string]::IsNullOrWhiteSpace($AuthorizedUserProgramsRoot) -and -not ([IO.Path]::GetFullPath($AuthorizedUserProgramsRoot).TrimEnd('\')).Equals([IO.Path]::GetFullPath([string]$interactiveIdentity.ProgramsRoot).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { throw 'Provided authorized Programs root does not match the interactive Windows user.' }
    $AuthorizedUserSid = [string]$interactiveIdentity.Sid
    $AuthorizedUserProgramsRoot = [string]$interactiveIdentity.ProgramsRoot
}

$layout = Get-QuietShieldProductionLayout -Version $Version
if (-not ([IO.Path]::GetFullPath($ProductRoot).TrimEnd('\')).Equals([string]$layout.ProductRoot, [StringComparison]::OrdinalIgnoreCase) -or
    -not ([IO.Path]::GetFullPath($StateRoot).TrimEnd('\')).Equals([string]$layout.StateRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Production installation is restricted to the exact Program Files and ProgramData QuietShield locations.'
}
if ($AuthorizedUserSid -notmatch '\AS-1-') { throw 'The installer did not provide a valid authorized Windows SID.' }
$userProgramsRoot = [IO.Path]::GetFullPath($AuthorizedUserProgramsRoot).TrimEnd('\')
if (-not $userProgramsRoot.EndsWith('\AppData\Local\Programs', [StringComparison]::OrdinalIgnoreCase)) { throw 'The authorized per-user Programs root is invalid.' }

[void](Test-QuietShieldComponentManifest -ComponentRoot $layout.AppRoot -ExpectedComponent 'QuietShield.App' -ExpectedVersion $Version)
[void](Test-QuietShieldComponentManifest -ComponentRoot $layout.ServiceRoot -ExpectedComponent 'QuietShield.Service' -ExpectedVersion $Version)
$serviceExecutable = Join-Path $layout.ServiceRoot 'QuietShield.Service.exe'
$enforcementScript = Join-Path $layout.ServiceRoot 'scripts\Invoke-ServiceFirewallPolicy.ps1'
$binaryPath = Get-QuietShieldProductionServiceCommandLine -Layout $layout
$services = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='QuietShieldService'" -ErrorAction SilentlyContinue)
if ($services.Count -gt 1) { throw 'The exact QuietShield service identity is ambiguous.' }
$ownershipExists = Test-Path -LiteralPath $layout.ServiceOwnershipPath -PathType Leaf
$previousOwned = $null
if ($services.Count -eq 1 -or $ownershipExists) {
    if (-not $ownershipExists) { throw 'A foreign service uses the exact QuietShield service name.' }
    $previousOwned = Test-QuietShieldProductionOwnership -OwnershipPath $layout.ServiceOwnershipPath -AllowAbsentService
}

$plan = [pscustomobject][ordered]@{
    status = 'ProductionServiceInstallationPlanValidated'
    serviceName = 'QuietShieldService'
    displayName = 'QuietShield Protection Service'
    version = $Version
    productRoot = $layout.ProductRoot
    serviceRoot = $layout.ServiceRoot
    stateRoot = $layout.StateRoot
    binaryPathName = $binaryPath
    startup = 'AutomaticDelayedStart'
    recovery = 'RestartAfter60SecondsThreeTimes'
    authorizedUserSid = $AuthorizedUserSid
    approvedProgramRoots = @([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles), [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86), $userProgramsRoot) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique
    createsFirewallRules = $false
    changesDns = $false
    modifyingCommandInvoked = $false
}
if ($WhatIfPreference) { $plan | ConvertTo-Json -Depth 6; return }
if (-not $ApprovedInstallerServiceRegistration) { throw 'Production service registration requires explicit installer approval.' }
if (-not (Test-QuietShieldAdministrator)) { throw 'Production service registration requires the normal elevated Windows installer boundary and never self-elevates.' }

$previousConfigBytes = $null
$previousOwnershipBytes = $null
$previousBinaryPath = $null
$previousWasRunning = $false
if ($null -ne $previousOwned) {
    $previousConfigBytes = [IO.File]::ReadAllBytes([string]$previousOwned.Manifest.configurationPath)
    $previousOwnershipBytes = [IO.File]::ReadAllBytes([string]$previousOwned.Path)
    $previousBinaryPath = [string]$previousOwned.Manifest.binaryPathName
    $previousWasRunning = $null -ne $previousOwned.Service -and [string]$previousOwned.Service.State -eq 'Running'
}

New-Item -ItemType Directory -Path $layout.StateRoot -Force | Out-Null
& icacls.exe $layout.StateRoot '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to secure the exact QuietShield production state directory.' }

$installationId = [Guid]::NewGuid()
if ($null -ne $previousOwned) { $installationId = [Guid][string]$previousOwned.Manifest.installationId }
$createdAt = [DateTimeOffset]::UtcNow
$production = [pscustomobject][ordered]@{
    schemaVersion = 1
    productMarker = 'QuietShield'
    purpose = 'QuietShieldProductionService'
    serviceName = 'QuietShieldService'
    installationId = $installationId.ToString('D')
    authorizedUserSid = $AuthorizedUserSid
    approvedProgramRoots = @($plan.approvedProgramRoots)
    enforcementScriptPath = $enforcementScript
    enforcementScriptSha256 = Get-QuietShieldFileSha256 -Path $enforcementScript
    createdAtUtc = $createdAt.ToString('O')
    payloadSha256 = ''
}
$production.payloadSha256 = Get-QuietShieldProductionServiceConfigurationPayloadHash -Configuration $production
$temporaryConfig = $layout.ProductionConfigurationPath + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
$createdService = $false
try {
    $production | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $temporaryConfig -Encoding UTF8
    [void](Test-QuietShieldProductionServiceConfiguration -Path $temporaryConfig)
    Move-Item -LiteralPath $temporaryConfig -Destination $layout.ProductionConfigurationPath -Force
    [void](Test-QuietShieldProductionServiceConfiguration -Path $layout.ProductionConfigurationPath)

    if ($services.Count -eq 1 -and [string]$services[0].State -ne 'Stopped') {
        Stop-Service -Name 'QuietShieldService' -Force
        (Get-Service -Name 'QuietShieldService').WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
    }
    if ($services.Count -eq 0) {
        New-Service -Name 'QuietShieldService' -BinaryPathName $binaryPath -DisplayName 'QuietShield Protection Service' -Description 'QuietShield persistent Program Connection Lock service.' -StartupType Automatic | Out-Null
        $createdService = $true
    }
    else {
        & sc.exe config 'QuietShieldService' 'binPath=' $binaryPath 'start=' 'delayed-auto' 'DisplayName=' 'QuietShield Protection Service' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Failed to update the exact QuietShield service registration.' }
    }
    & sc.exe config 'QuietShieldService' 'start=' 'delayed-auto' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to configure automatic delayed start.' }
    & sc.exe description 'QuietShieldService' 'QuietShield persistent Program Connection Lock service.' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to configure the exact service description.' }
    & sc.exe failure 'QuietShieldService' 'reset=' '86400' 'actions=' 'restart/60000/restart/60000/restart/60000' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to configure exact service recovery.' }
    & sc.exe failureflag 'QuietShieldService' '1' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to configure non-crash failure recovery.' }

    $ownership = [pscustomobject][ordered]@{
        schemaVersion = 1; productMarker = 'QuietShield'; purpose = 'QuietShieldProductionServiceOwnership'; installerAppId = $script:QuietShieldInstallerAppId
        version = $Version; serviceName = 'QuietShieldService'; displayName = 'QuietShield Protection Service'; productRoot = $layout.ProductRoot; serviceRoot = $layout.ServiceRoot
        executablePath = $serviceExecutable; executableSha256 = Get-QuietShieldFileSha256 -Path $serviceExecutable
        configurationPath = $layout.ProductionConfigurationPath; configurationSha256 = Get-QuietShieldFileSha256 -Path $layout.ProductionConfigurationPath
        binaryPathName = $binaryPath; authorizedUserSid = $AuthorizedUserSid; installationId = $installationId.ToString('D'); installedAtUtc = $createdAt.ToString('O'); payloadSha256 = ''
    }
    $ownership.payloadSha256 = Get-QuietShieldProductionOwnershipPayloadHash -Manifest $ownership
    $ownership | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $layout.ServiceOwnershipPath -Encoding UTF8
    [void](Test-QuietShieldProductionOwnership -OwnershipPath $layout.ServiceOwnershipPath)
    # R4.2.26 installer stable service start
    # Reaching RUNNING once is not sufficient. Require a bounded stability window.
    # Exactly one retry is permitted; a second drop fails installation.
    $serviceStable = $false
    $serviceStartAttempt = 0
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        $serviceStartAttempt = $attempt
        if ($attempt -gt 1) { Start-Sleep -Seconds 2 }
        $serviceController = Get-Service -Name 'QuietShieldService' -ErrorAction Stop
        if ($serviceController.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
            Start-Service -Name 'QuietShieldService'
        }
        $serviceController = Get-Service -Name 'QuietShieldService' -ErrorAction Stop
        $serviceController.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
        Start-Sleep -Seconds 10
        $serviceController.Refresh()
        if ($serviceController.Status -eq [ServiceProcess.ServiceControllerStatus]::Running) {
            $serviceStable = $true
            break
        }
    }
    if (-not $serviceStable) {
        throw ('QuietShieldService did not remain RUNNING after installer registration; bounded start attempts=' + $serviceStartAttempt)
    }
    [pscustomobject]@{ status = 'Installed'; serviceName = 'QuietShieldService'; version = $Version; installationId = $installationId.ToString('D'); serviceRunning = $true; firewallRulesCreated = 0; dnsChanged = $false; restartRequired = $false } | ConvertTo-Json -Compress
}
catch {
    if (Test-Path -LiteralPath $temporaryConfig) { Remove-Item -LiteralPath $temporaryConfig -Force }
    if ($createdService) { & sc.exe delete 'QuietShieldService' | Out-Null }
    elseif ($null -ne $previousBinaryPath) {
        & sc.exe config 'QuietShieldService' 'binPath=' $previousBinaryPath | Out-Null
        if ($previousWasRunning) { Start-Service -Name 'QuietShieldService' -ErrorAction SilentlyContinue }
    }
    if ($null -ne $previousConfigBytes) { [IO.File]::WriteAllBytes($layout.ProductionConfigurationPath, $previousConfigBytes) }
    elseif (Test-Path -LiteralPath $layout.ProductionConfigurationPath) { Remove-Item -LiteralPath $layout.ProductionConfigurationPath -Force }
    if ($null -ne $previousOwnershipBytes) { [IO.File]::WriteAllBytes($layout.ServiceOwnershipPath, $previousOwnershipBytes) }
    elseif (Test-Path -LiteralPath $layout.ServiceOwnershipPath) { Remove-Item -LiteralPath $layout.ServiceOwnershipPath -Force }
    throw
}
