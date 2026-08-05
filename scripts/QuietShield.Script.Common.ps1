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

function Get-QuietShieldVisualStudio2026Instance {
    $vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) {
        throw 'vswhere.exe was not found.'
    }

    $json = & $vswhere -all -products Microsoft.VisualStudio.Product.Community -format json -utf8
    if ($LASTEXITCODE -ne 0) {
        throw 'vswhere failed.'
    }

    $instances = @()
    foreach ($instance in ($json | ConvertFrom-Json)) {
        $instances += $instance
    }

    $matches = @($instances | Where-Object {
        $_.installationPath -eq 'D:\Microsoft Visual Studio\2026\Community' -and
        $_.installationVersion -eq '18.8.12023.21' -and
        $_.isComplete -eq $true -and
        $_.isLaunchable -eq $true
    })

    if ($matches.Count -ne 1) {
        throw 'The validated Visual Studio 2026 Community 18.8.2 instance was not found exactly once.'
    }

    return $matches[0]
}

function Assert-QuietShieldToolchain {
    $sdkVersion = (& dotnet --version | Select-Object -First 1).Trim()
    if ($LASTEXITCODE -ne 0 -or $sdkVersion -ne '10.0.302') {
        throw ("Expected .NET SDK 10.0.302; actual: {0}" -f $sdkVersion)
    }

    $instance = Get-QuietShieldVisualStudio2026Instance
    Write-Output ("Visual Studio: {0} at {1}" -f $instance.installationVersion, $instance.installationPath)
    Write-Output (".NET SDK: {0}" -f $sdkVersion)
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

function Get-QuietShieldSafetySnapshot {
    $firewallData = @()
    $dnsData = @()
    $adapterData = @()
    $startupData = @()

    try {
        $firewallData = @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction)
    }
    catch {
        $firewallData = @('Unavailable')
    }

    try {
        $dnsData = @(Get-DnsClientServerAddress -ErrorAction Stop | Select-Object InterfaceIndex, AddressFamily, ServerAddresses)
    }
    catch {
        $dnsData = @('Unavailable')
    }

    try {
        $adapterData = @(Get-NetAdapter -ErrorAction Stop | Select-Object InterfaceGuid, Status, LinkSpeed, MacAddress)
    }
    catch {
        $adapterData = @('Unavailable')
    }

    foreach ($path in @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )) {
        if (Test-Path -LiteralPath $path) {
            $startupItem = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
            foreach ($property in @($startupItem.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Sort-Object Name)) {
                $startupData += [pscustomobject]@{
                    Path = $path
                    Name = $property.Name
                    Value = [string]$property.Value
                }
            }
        }
    }

    $services = @(Get-Service -Name 'QuietShield*' -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType)

    return [pscustomobject]@{
        IsAdministrator = Test-QuietShieldAdministrator
        QuietShieldServiceCount = $services.Count
        QuietShieldServiceHash = Get-QuietShieldStringHash (($services | ConvertTo-Json -Depth 4 -Compress) -join '')
        FirewallHash = Get-QuietShieldStringHash (($firewallData | ConvertTo-Json -Depth 4 -Compress) -join '')
        DnsHash = Get-QuietShieldStringHash (($dnsData | ConvertTo-Json -Depth 5 -Compress) -join '')
        AdapterHash = Get-QuietShieldStringHash (($adapterData | ConvertTo-Json -Depth 4 -Compress) -join '')
        StartupHash = Get-QuietShieldStringHash (($startupData | ConvertTo-Json -Depth 5 -Compress) -join '')
    }
}
