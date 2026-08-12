Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:QuietShieldRepositoryRoot = Split-Path -Parent $PSScriptRoot
$script:QuietShieldLogStarted = $false

function Get-QuietShieldRepositoryRoot {
    return $script:QuietShieldRepositoryRoot
}

function Assert-QuietShieldPowerShell51 {
    if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
        throw 'QuietShield scripts require Windows PowerShell 5.1.'
    }
}

function Test-QuietShieldAdministrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-QuietShieldNonElevated {
    if (Test-QuietShieldAdministrator) {
        throw 'QuietShield foundation scripts must run without Administrator elevation.'
    }
}

function Initialize-QuietShieldProcessEnvironment {
    $artifacts = Join-Path $script:QuietShieldRepositoryRoot 'artifacts'
    $env:DOTNET_CLI_HOME = Join-Path $artifacts 'dotnet-home'
    $env:NUGET_PACKAGES = Join-Path $artifacts 'packages'
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
    $env:DOTNET_NOLOGO = '1'
    $env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'

    foreach ($path in @($artifacts, $env:DOTNET_CLI_HOME, $env:NUGET_PACKAGES)) {
        if (-not (Test-Path -LiteralPath $path)) {
            [void](New-Item -ItemType Directory -Path $path -Force)
        }
    }
}

function Start-QuietShieldLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $logDirectory = Join-Path $script:QuietShieldRepositoryRoot 'logs'
    if (-not (Test-Path -LiteralPath $logDirectory)) {
        [void](New-Item -ItemType Directory -Path $logDirectory -Force)
    }

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $logPath = Join-Path $logDirectory ($Name + '-' + $timestamp + '.log')
    if ($WhatIfPreference) {
        Write-Host ('WhatIf log path: ' + $logPath)
        $script:QuietShieldLogStarted = $false
        return $logPath
    }
    Start-Transcript -LiteralPath $logPath -Force | Out-Null
    $script:QuietShieldLogStarted = $true
    Write-Host ('Log: ' + $logPath)
    return $logPath
}

function Stop-QuietShieldLog {
    if ($script:QuietShieldLogStarted) {
        Stop-Transcript | Out-Null
        $script:QuietShieldLogStarted = $false
    }
}

function Invoke-QuietShieldCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList
    )

    Write-Output ('> ' + $FilePath + ' ' + ($ArgumentList -join ' '))
    & $FilePath @ArgumentList
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw ("Command failed with exit code {0}: {1}" -f $exitCode, $FilePath)
    }
}

function Test-QuietShieldVisualStudioCompatibility {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RequiredFeatureLine,
        [Parameter(Mandatory = $true)][string]$MinimumServicingVersion,
        [Parameter(Mandatory = $true)][string]$ResolvedProductVersion,
        [Parameter(Mandatory = $true)][string]$InstallationVersion,
        [Parameter(Mandatory = $true)][bool]$IsComplete,
        [Parameter(Mandatory = $true)][bool]$IsLaunchable,
        [Parameter(Mandatory = $true)][bool]$IsPrerelease
    )

    if (-not $IsComplete -or -not $IsLaunchable -or $IsPrerelease) { return $false }
    if ($RequiredFeatureLine -notmatch '\A(?<major>\d+)\.(?<minor>\d+)\z') { return $false }
    $RequiredMajor = [int]$Matches.major
    $RequiredMinor = [int]$Matches.minor
    if ($MinimumServicingVersion -notmatch '\A(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)\z') { return $false }
    $MinimumMajor = [int]$Matches.major
    $MinimumMinor = [int]$Matches.minor
    $MinimumPatch = [int]$Matches.patch
    if ($ResolvedProductVersion -notmatch '\A(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)\z') { return $false }
    $ResolvedMajor = [int]$Matches.major
    $ResolvedMinor = [int]$Matches.minor
    $ResolvedPatch = [int]$Matches.patch
    if ($InstallationVersion -notmatch '\A(?<major>\d+)\.(?<minor>\d+)\.\d+\.\d+\z') { return $false }
    $InstallationMajor = [int]$Matches.major
    $InstallationMinor = [int]$Matches.minor

    return $MinimumMajor -eq $RequiredMajor -and
        $MinimumMinor -eq $RequiredMinor -and
        $ResolvedMajor -eq $RequiredMajor -and
        $ResolvedMinor -eq $RequiredMinor -and
        $ResolvedPatch -ge $MinimumPatch -and
        $InstallationMajor -eq $RequiredMajor -and
        $InstallationMinor -eq $RequiredMinor
}

function Get-QuietShieldVisualStudio2026Instance {
    $vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) {
        throw 'vswhere.exe was not found.'
    }

    $json = & $vswhere -all -products Microsoft.VisualStudio.Product.Community -requires Microsoft.VisualStudio.Workload.ManagedDesktop Microsoft.VisualStudio.Component.NuGet Microsoft.Component.MSBuild -format json -utf8
    if ($LASTEXITCODE -ne 0) {
        throw 'vswhere failed.'
    }

    $instances = @()
    foreach ($instance in ($json | ConvertFrom-Json)) {
        $instances += $instance
    }

    $matches = @($instances | Where-Object {
        $_.installationPath -eq 'D:\Microsoft Visual Studio\2026\Community' -and
        (Test-QuietShieldVisualStudioCompatibility `
            -RequiredFeatureLine '18.8' `
            -MinimumServicingVersion '18.8.2' `
            -ResolvedProductVersion ([string]$_.catalog.productDisplayVersion) `
            -InstallationVersion ([string]$_.installationVersion) `
            -IsComplete ([bool]$_.isComplete) `
            -IsLaunchable ([bool]$_.isLaunchable) `
            -IsPrerelease ([bool]$_.isPrerelease))
    })

    if ($matches.Count -ne 1) {
        throw 'A complete, launchable Visual Studio 2026 Community 18.8.x instance at the validated path with ManagedDesktop, NuGet, and MSBuild was not found exactly once.'
    }

    return $matches[0]
}

function Test-QuietShieldDotNetSdkCompatibility {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RequestedVersion,
        [Parameter(Mandatory = $true)][string]$ResolvedVersion,
        [Parameter(Mandatory = $true)][string]$RollForward,
        [Parameter(Mandatory = $true)][bool]$AllowPrerelease
    )

    if ($RollForward -cne 'latestPatch') { return $false }
    if ($RequestedVersion -notmatch '\A(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)\z') { return $false }
    $RequestedMajor = [int]$Matches.major
    $RequestedMinor = [int]$Matches.minor
    $RequestedPatch = [int]$Matches.patch
    if ($ResolvedVersion -notmatch '\A(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)\z') {
        return $false
    }
    $ResolvedMajor = [int]$Matches.major
    $ResolvedMinor = [int]$Matches.minor
    $ResolvedPatch = [int]$Matches.patch
    if (-not $AllowPrerelease -and $ResolvedVersion.Contains('-')) { return $false }

    $RequestedFeatureBand = [Math]::Floor($RequestedPatch / 100)
    $ResolvedFeatureBand = [Math]::Floor($ResolvedPatch / 100)
    return $ResolvedMajor -eq $RequestedMajor -and
        $ResolvedMinor -eq $RequestedMinor -and
        $ResolvedFeatureBand -eq $RequestedFeatureBand -and
        $ResolvedPatch -ge $RequestedPatch
}

function Get-QuietShieldResolvedDotNetSdkVersion {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$RepositoryRoot)

    $StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $StartInfo.FileName = 'dotnet'
    $StartInfo.Arguments = '--version'
    $StartInfo.WorkingDirectory = [IO.Path]::GetFullPath($RepositoryRoot)
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    $SdkProcess = New-Object System.Diagnostics.Process
    $SdkProcess.StartInfo = $StartInfo
    if (-not $SdkProcess.Start()) { throw 'dotnet --version could not start.' }
    $StandardOutputTask = $SdkProcess.StandardOutput.ReadToEndAsync()
    $StandardErrorTask = $SdkProcess.StandardError.ReadToEndAsync()
    if (-not $SdkProcess.WaitForExit(15000)) { throw 'dotnet --version exceeded its bounded timeout.' }
    $SdkProcess.WaitForExit()
    $SdkProcess.Refresh()
    $StandardOutput = $StandardOutputTask.GetAwaiter().GetResult()
    $StandardError = $StandardErrorTask.GetAwaiter().GetResult()
    $SdkExitCode = $SdkProcess.ExitCode
    $SdkProcess.Dispose()
    if ($SdkExitCode -ne 0) { throw ('dotnet --version failed: ' + $StandardError.Trim()) }
    return ([string]$StandardOutput).Trim()
}

function Assert-QuietShieldToolchain {
    $RepositoryRoot = Get-QuietShieldRepositoryRoot
    $GlobalJsonPath = Join-Path $RepositoryRoot 'global.json'
    if (-not (Test-Path -LiteralPath $GlobalJsonPath -PathType Leaf)) { throw 'The repository global.json is missing.' }
    $GlobalJson = Get-Content -LiteralPath $GlobalJsonPath -Raw | ConvertFrom-Json
    $RequestedSdkVersion = [string]$GlobalJson.sdk.version
    $RollForward = [string]$GlobalJson.sdk.rollForward
    $AllowPrerelease = [bool]$GlobalJson.sdk.allowPrerelease
    $ResolvedSdkVersion = Get-QuietShieldResolvedDotNetSdkVersion -RepositoryRoot $RepositoryRoot
    if (-not (Test-QuietShieldDotNetSdkCompatibility -RequestedVersion $RequestedSdkVersion -ResolvedVersion $ResolvedSdkVersion -RollForward $RollForward -AllowPrerelease $AllowPrerelease)) {
        throw ("Resolved .NET SDK {0} is incompatible with global.json request {1} ({2}, allowPrerelease={3})." -f $ResolvedSdkVersion, $RequestedSdkVersion, $RollForward, $AllowPrerelease)
    }

    $instance = Get-QuietShieldVisualStudio2026Instance
    Write-Output ("Visual Studio: {0} ({1}) at {2}" -f $instance.catalog.productDisplayVersion, $instance.installationVersion, $instance.installationPath)
    Write-Output (".NET SDK: {0} (global.json requested {1}; {2})" -f $ResolvedSdkVersion, $RequestedSdkVersion, $RollForward)
}

function Get-QuietShieldMSBuildPath {
    $instance = Get-QuietShieldVisualStudio2026Instance
    $msbuild = Join-Path $instance.installationPath 'MSBuild\Current\Bin\MSBuild.exe'
    if (-not (Test-Path -LiteralPath $msbuild)) {
        throw ("Visual Studio 2026 MSBuild was not found: {0}" -f $msbuild)
    }

    return $msbuild
}

function Get-QuietShieldStringHash {
    param(
        [AllowEmptyString()]
        [string]$Value
    )

    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        return ([System.BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '')
    }
    finally {
        $algorithm.Dispose()
    }
}

function ConvertTo-QuietShieldCanonicalDnsSnapshotData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Rows
    )

    $canonicalRows = @()
    foreach ($row in @($Rows)) {
        $serverAddresses = @()
        foreach ($serverAddress in @($row.ServerAddresses)) {
            $serverAddresses += [string]$serverAddress
        }

        $canonicalRows += [pscustomobject][ordered]@{
            InterfaceIndex = [int]$row.InterfaceIndex
            AddressFamily = [int]$row.AddressFamily
            ServerAddresses = $serverAddresses
        }
    }

    return @($canonicalRows | Sort-Object -Property InterfaceIndex, AddressFamily)
}

function ConvertTo-QuietShieldCanonicalAdapterIdentityData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Rows
    )

    $canonicalRows = @()
    foreach ($row in @($Rows)) {
        $canonicalRows += [pscustomobject][ordered]@{
            InterfaceGuid = [string]$row.InterfaceGuid
            InterfaceIndex = [int]$row.InterfaceIndex
            Name = [string]$row.Name
            InterfaceDescription = [string]$row.InterfaceDescription
        }
    }
    return @($canonicalRows | Sort-Object -Property InterfaceGuid, InterfaceIndex, Name)
}

function ConvertTo-QuietShieldCanonicalAdapterConfigurationData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Rows
    )

    $canonicalRows = @()
    foreach ($row in @($Rows)) {
        $canonicalRows += [pscustomobject][ordered]@{
            InterfaceIndex = [int]$row.InterfaceIndex
            AddressFamily = [int]$row.AddressFamily
            Dhcp = [int]$row.Dhcp
            RouterDiscovery = [int]$row.RouterDiscovery
            NlMtu = [uint32]$row.NlMtu
        }
    }
    return @($canonicalRows | Sort-Object -Property InterfaceIndex, AddressFamily)
}

function ConvertTo-QuietShieldCanonicalAdapterOperationalData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Rows
    )

    $canonicalRows = @()
    foreach ($row in @($Rows)) {
        $canonicalRows += [pscustomobject][ordered]@{
            InterfaceGuid = [string]$row.InterfaceGuid
            InterfaceIndex = [int]$row.InterfaceIndex
            Name = [string]$row.Name
            InterfaceDescription = [string]$row.InterfaceDescription
            Status = [string]$row.Status
        }
    }
    return @($canonicalRows | Sort-Object -Property InterfaceGuid, InterfaceIndex, Name)
}

function Test-QuietShieldVpnOrVirtualAdapter {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Adapter)

    $identity = ([string]$Adapter.Name + ' ' + [string]$Adapter.InterfaceDescription)
    return $identity -match '(?i)(vpn|openvpn|surfshark|tap-windows|wireguard|tailscale|zerotier|virtual|wi-fi direct|hyper-v|vmware|virtualbox|wsl|docker|tunnel)'
}

function Test-QuietShieldSurfsharkOrOpenVpnAdapter {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Adapter)

    $identity = ([string]$Adapter.Name + ' ' + [string]$Adapter.InterfaceDescription)
    return $identity -match '(?i)(surfshark|openvpn)'
}

function Get-QuietShieldVpnAndVirtualAdapterOperationalState {
    [CmdletBinding()]
    param()

    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { Test-QuietShieldVpnOrVirtualAdapter -Adapter $_ })
    return @(ConvertTo-QuietShieldCanonicalAdapterOperationalData -Rows $adapters)
}

function Assert-QuietShieldSurfsharkAndOpenVpnDisconnected {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object[]]$OperationalState)

    $connected = @($OperationalState | Where-Object {
        (Test-QuietShieldSurfsharkOrOpenVpnAdapter -Adapter $_) -and [string]$_.Status -notin @('Disconnected', 'Disabled', 'Not Present')
    })
    if ($connected.Count -ne 0) {
        throw ('Surfshark/OpenVPN must remain disconnected for the Firewall rehearsal. Active adapter: ' + [string]$connected[0].Name)
    }
}

function Test-QuietShieldVpnAndVirtualAdapterStability {
    [CmdletBinding()]
    param([ValidateRange(15, 60)][int]$DurationSeconds = 15)

    $initial = @(Get-QuietShieldVpnAndVirtualAdapterOperationalState)
    Assert-QuietShieldSurfsharkAndOpenVpnDisconnected -OperationalState $initial
    $initialHash = Get-QuietShieldStringHash (($initial | ConvertTo-Json -Depth 5 -Compress) -join '')
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    try {
        while ($stopwatch.Elapsed.TotalSeconds -lt $DurationSeconds) {
            Start-Sleep -Milliseconds 500
            $observed = @(Get-QuietShieldVpnAndVirtualAdapterOperationalState)
            Assert-QuietShieldSurfsharkAndOpenVpnDisconnected -OperationalState $observed
            $observedHash = Get-QuietShieldStringHash (($observed | ConvertTo-Json -Depth 5 -Compress) -join '')
            if ($observedHash -cne $initialHash) {
                throw 'A VPN or virtual-adapter operational state changed during the required stability window.'
            }
        }
    }
    finally {
        $stopwatch.Stop()
    }

    return [pscustomobject][ordered]@{
        Stable = $true
        DurationSeconds = $DurationSeconds
        StateHash = $initialHash
        SurfsharkOpenVpnDisconnected = $true
        Adapters = $initial
    }
}

function Get-QuietShieldAdapterOperationalEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object[]]$Before,
        [Parameter(Mandatory = $true)][object[]]$After
    )

    $beforeByKey = @{}
    $afterByKey = @{}
    foreach ($row in @($Before)) {
        $key = [string]$row.InterfaceGuid
        if ([string]::IsNullOrWhiteSpace($key)) { $key = ([string]$row.InterfaceIndex + '|' + [string]$row.Name) }
        $beforeByKey[$key] = $row
    }
    foreach ($row in @($After)) {
        $key = [string]$row.InterfaceGuid
        if ([string]::IsNullOrWhiteSpace($key)) { $key = ([string]$row.InterfaceIndex + '|' + [string]$row.Name) }
        $afterByKey[$key] = $row
    }

    $events = @()
    $keys = @($beforeByKey.Keys + $afterByKey.Keys | Sort-Object -Unique)
    foreach ($key in $keys) {
        $beforeRow = $beforeByKey[$key]
        $afterRow = $afterByKey[$key]
        $beforeStatus = '[absent]'
        if ($null -ne $beforeRow) { $beforeStatus = [string]$beforeRow.Status }
        $afterStatus = '[absent]'
        if ($null -ne $afterRow) { $afterStatus = [string]$afterRow.Status }
        if ($beforeStatus -ceq $afterStatus) { continue }
        $identity = $beforeRow
        if ($null -ne $afterRow) { $identity = $afterRow }
        $classification = 'PhysicalOrOther'
        if (Test-QuietShieldVpnOrVirtualAdapter -Adapter $identity) { $classification = 'VpnOrVirtual' }
        $events += [pscustomobject][ordered]@{
            Event = 'EnvironmentalAdapterOperationalTransition'
            InterfaceGuid = [string]$identity.InterfaceGuid
            InterfaceIndex = [int]$identity.InterfaceIndex
            AdapterName = [string]$identity.Name
            Classification = $classification
            BeforeStatus = $beforeStatus
            AfterStatus = $afterStatus
        }
    }
    return @($events)
}

function Compare-QuietShieldSafetySnapshots {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Before,
        [Parameter(Mandatory = $true)]$After
    )

    $persistentProperties = @(
        'QuietShieldServiceHash', 'FirewallHash', 'QuietShieldFirewallRuleHash', 'DnsHash',
        'AdapterIdentityHash', 'AdapterConfigurationHash', 'StartupHash', 'QuietShieldWfpHash', 'QuietShieldRegistryHash'
    )
    $differences = @()
    foreach ($property in $persistentProperties) {
        $beforeProperty = $Before.PSObject.Properties[$property]
        $afterProperty = $After.PSObject.Properties[$property]
        if ($null -eq $beforeProperty -or $null -eq $afterProperty -or [string]$beforeProperty.Value -cne [string]$afterProperty.Value) {
            $differences += $property
        }
    }
    $events = @(Get-QuietShieldAdapterOperationalEvents -Before @($Before.AdapterOperationalState) -After @($After.AdapterOperationalState))
    return [pscustomobject][ordered]@{
        PersistentMatch = ($differences.Count -eq 0)
        PersistentDifferences = $differences
        AdapterOperationalChanged = ($events.Count -ne 0)
        AdapterOperationalEvents = $events
    }
}

function Get-QuietShieldSafetySnapshot {
    $firewallData = @()
    $dnsData = @()
    $adapterIdentityData = @()
    $adapterConfigurationData = @()
    $adapterOperationalData = @()
    $quietShieldFirewallRuleData = @()
    $startupData = @()
    $wfpData = @()
    $quietShieldRegistryData = @()

    try {
        $firewallData = @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction)
    }
    catch {
        $firewallData = @('Unavailable')
    }

    try {
        $quietShieldFirewallRuleData = @(
            Get-NetFirewallRule -Name 'QuietShield.*' -ErrorAction SilentlyContinue |
                Select-Object Name, DisplayName, Description, Enabled, Direction, Action, Profile, EdgeTraversalPolicy |
                Sort-Object -Property Name
        )
    }
    catch {
        $quietShieldFirewallRuleData = @('Unavailable')
    }

    try {
        $observedDnsData = @(Get-DnsClientServerAddress -ErrorAction Stop | Select-Object InterfaceIndex, AddressFamily, ServerAddresses)
        $dnsData = @(ConvertTo-QuietShieldCanonicalDnsSnapshotData -Rows $observedDnsData)
    }
    catch {
        $dnsData = @('Unavailable')
    }

    try {
        $adapterRows = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
        $adapterIdentityData = @(ConvertTo-QuietShieldCanonicalAdapterIdentityData -Rows $adapterRows)
        $adapterOperationalData = @(ConvertTo-QuietShieldCanonicalAdapterOperationalData -Rows $adapterRows)
    }
    catch {
        $adapterIdentityData = @('Unavailable')
        $adapterOperationalData = @('Unavailable')
    }

    try {
        $adapterConfigurationRows = @(
            Get-NetIPInterface -ErrorAction Stop |
                Select-Object InterfaceIndex, AddressFamily, Dhcp, RouterDiscovery, NlMtu
        )
        $adapterConfigurationData = @(ConvertTo-QuietShieldCanonicalAdapterConfigurationData -Rows $adapterConfigurationRows)
    }
    catch {
        $adapterConfigurationData = @('Unavailable')
    }

    foreach ($path in @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )) {
        if (Test-Path -LiteralPath $path) {
            $startupItem = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
            foreach ($property in @($startupItem.PSObject.Properties | Where-Object { $_.Name -like 'QuietShield*' } | Sort-Object Name)) {
                $startupData += [pscustomobject]@{
                    Path = $path
                    Name = $property.Name
                }
            }
        }
    }

    $services = @(Get-Service -Name 'QuietShield*' -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType)

    $providerGuid = '{F79D8C43-A343-4A05-BF03-4DA61BDF8498}'
    $sublayerGuid = '{5D56C870-CF61-4BA7-B59E-89B4B2364A03}'
    foreach ($path in @(
        ('HKLM:\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\Persistent\Provider\' + $providerGuid),
        ('HKLM:\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\Persistent\SubLayer\' + $sublayerGuid),
        'HKLM:\SYSTEM\CurrentControlSet\Services\QuietShieldWfpCallout',
        'HKLM:\SYSTEM\CurrentControlSet\Services\QuietShield.Callout',
        'HKLM:\SYSTEM\CurrentControlSet\Services\QuietShieldDriver'
    )) {
        $wfpData += [pscustomobject]@{
            Path = $path
            Exists = Test-Path -LiteralPath $path
        }
    }

    foreach ($path in @(
        'HKCU:\Software\QuietShield',
        'HKLM:\Software\QuietShield',
        'HKLM:\Software\WOW6432Node\QuietShield',
        'HKLM:\SYSTEM\CurrentControlSet\Services\QuietShield',
        'HKLM:\SYSTEM\CurrentControlSet\Services\QuietShield.Service'
    )) {
        if (Test-Path -LiteralPath $path) {
            foreach ($item in @((Get-Item -LiteralPath $path -ErrorAction Stop)) + @(Get-ChildItem -LiteralPath $path -Recurse -ErrorAction Stop)) {
                $valueNames = @($item.Property | Sort-Object)
                $quietShieldRegistryData += [pscustomobject]@{
                    Path = $item.Name
                    ValueNames = $valueNames
                }
            }
        }
    }

    $adapterIdentityHash = Get-QuietShieldStringHash (($adapterIdentityData | ConvertTo-Json -Depth 5 -Compress) -join '')
    $adapterConfigurationHash = Get-QuietShieldStringHash (($adapterConfigurationData | ConvertTo-Json -Depth 5 -Compress) -join '')
    $adapterOperationalHash = Get-QuietShieldStringHash (($adapterOperationalData | ConvertTo-Json -Depth 5 -Compress) -join '')
    return [pscustomobject]@{
        IsAdministrator = Test-QuietShieldAdministrator
        QuietShieldServiceCount = $services.Count
        QuietShieldServiceHash = Get-QuietShieldStringHash (($services | ConvertTo-Json -Depth 4 -Compress) -join '')
        FirewallHash = Get-QuietShieldStringHash (($firewallData | ConvertTo-Json -Depth 4 -Compress) -join '')
        QuietShieldFirewallRuleHash = Get-QuietShieldStringHash (($quietShieldFirewallRuleData | ConvertTo-Json -Depth 5 -Compress) -join '')
        DnsHash = Get-QuietShieldStringHash (($dnsData | ConvertTo-Json -Depth 5 -Compress) -join '')
        AdapterHash = Get-QuietShieldStringHash ($adapterIdentityHash + '|' + $adapterConfigurationHash)
        AdapterIdentityHash = $adapterIdentityHash
        AdapterConfigurationHash = $adapterConfigurationHash
        AdapterOperationalHash = $adapterOperationalHash
        AdapterOperationalState = $adapterOperationalData
        StartupHash = Get-QuietShieldStringHash (($startupData | ConvertTo-Json -Depth 5 -Compress) -join '')
        QuietShieldWfpHash = Get-QuietShieldStringHash (($wfpData | ConvertTo-Json -Depth 4 -Compress) -join '')
        QuietShieldRegistryHash = Get-QuietShieldStringHash (($quietShieldRegistryData | ConvertTo-Json -Depth 5 -Compress) -join '')
    }
}
