[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [ValidateSet('x64')]
    [string]$Platform = 'x64'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')

Assert-QuietShieldPowerShell51
Assert-QuietShieldNonElevated
Initialize-QuietShieldProcessEnvironment
$logPath = Start-QuietShieldLog -Name ('build-' + $Configuration.ToLowerInvariant())

try {
    Assert-QuietShieldToolchain
    $root = Get-QuietShieldRepositoryRoot
    $solution = Join-Path $root 'QuietShield.sln'
    $platformProperty = '-p:Platform=' + $Platform
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @('restore', $solution, $platformProperty)
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @('build', $solution, '--configuration', $Configuration, '--no-restore', $platformProperty)
    Write-Output ("QuietShield {0} {1} build succeeded." -f $Configuration, $Platform)
}
finally {
    Stop-QuietShieldLog
}
