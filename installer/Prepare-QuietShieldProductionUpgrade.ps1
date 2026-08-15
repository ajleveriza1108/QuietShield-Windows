[CmdletBinding()]
param(
    [switch]$ApprovedInstallerServiceQuiesce,
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$ProductRoot,
    [Parameter(Mandatory = $true)][string]$StateRoot
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ServiceActivation.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'QuietShield.Installer.Common.ps1')
Assert-QuietShieldPowerShell51
if (-not $ApprovedInstallerServiceQuiesce) { throw 'Pre-copy service quiesce requires explicit installer approval.' }
if (-not (Test-QuietShieldAdministrator)) { throw 'Pre-copy service quiesce requires the already-elevated Windows installer boundary.' }
$layout = Get-QuietShieldProductionLayout -Version $Version
if (-not ([IO.Path]::GetFullPath($ProductRoot).TrimEnd('\')).Equals([string]$layout.ProductRoot,[StringComparison]::OrdinalIgnoreCase) -or
    -not ([IO.Path]::GetFullPath($StateRoot).TrimEnd('\')).Equals([string]$layout.StateRoot,[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Pre-copy quiesce is restricted to the exact QuietShield Program Files and ProgramData roots.'
}
function Get-QuietShieldActiveLoopbackAdapterCount {
    $count = 0
    foreach ($adapter in @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })) {
        try {
            $servers = @((Get-DnsClientServerAddress -InterfaceIndex ([int]$adapter.ifIndex) -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses)
            if (@($servers | Where-Object { [string]$_ -eq '127.0.0.1' }).Count -gt 0) { $count++ }
        }
        catch { }
    }
    return $count
}
$services = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='QuietShieldService'" -ErrorAction SilentlyContinue)
if ($services.Count -gt 1) { throw 'The exact QuietShield service identity is ambiguous.' }
if ($services.Count -eq 0) {
    if ((Get-QuietShieldActiveLoopbackAdapterCount) -gt 0) { throw 'QuietShieldService is absent while loopback DNS remains active; refusing file replacement.' }
    [pscustomobject]@{ status='NoExistingService'; serviceStopped=$true; dnsLoopbackAdapters=0 } | ConvertTo-Json -Compress
    return
}
$ownershipPath = Join-Path $layout.StateRoot 'service-ownership.json'
$owned = Test-QuietShieldProductionOwnership -OwnershipPath $ownershipPath
if ($null -eq $owned.Service) { throw 'The owned QuietShield service disappeared during pre-copy validation.' }
if ([string]$owned.Service.State -ne 'Stopped') {
    Stop-Service -Name 'QuietShieldService' -Force
    (Get-Service -Name 'QuietShieldService').WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(30))
}
$deadline = (Get-Date).AddSeconds(15)
do {
    $loopback = Get-QuietShieldActiveLoopbackAdapterCount
    if ($loopback -eq 0) { break }
    Start-Sleep -Milliseconds 500
} while ((Get-Date) -lt $deadline)
if ($loopback -ne 0) { throw 'Owned QuietShield service stopped but loopback DNS was not restored; refusing file replacement.' }
[pscustomobject]@{ status='OwnedServiceQuiesced'; serviceStopped=$true; dnsLoopbackAdapters=0; ownershipPayloadSha256=[string]$owned.Manifest.payloadSha256 } | ConvertTo-Json -Compress