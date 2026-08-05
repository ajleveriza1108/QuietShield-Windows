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
$logPath = Start-QuietShieldLog -Name ('test-' + $Configuration.ToLowerInvariant())

try {
    Assert-QuietShieldToolchain
    $root = Get-QuietShieldRepositoryRoot
    $solution = Join-Path $root 'QuietShield.sln'
    $results = Join-Path $root ('artifacts\test-results\' + $Configuration)
    $loggerArgument = 'trx;LogFileName=QuietShield-' + $Configuration + '.trx'
    [void](New-Item -ItemType Directory -Path $results -Force)
    $platformProperty = '-p:Platform=' + $Platform
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @('restore', $solution, $platformProperty)
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @(
        'test',
        $solution,
        '--configuration',
        $Configuration,
        '--no-restore',
        $platformProperty,
        '--results-directory',
        $results,
        '--logger',
        $loggerArgument
    )
    Write-Output ("QuietShield {0} automated tests succeeded." -f $Configuration)
}
finally {
    Stop-QuietShieldLog
}
