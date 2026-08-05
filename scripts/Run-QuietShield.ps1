[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ApplicationArguments
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')

Assert-QuietShieldPowerShell51
Assert-QuietShieldNonElevated
Initialize-QuietShieldProcessEnvironment
$logPath = Start-QuietShieldLog -Name ('run-' + $Configuration.ToLowerInvariant())

try {
    Assert-QuietShieldToolchain
    $root = Get-QuietShieldRepositoryRoot
    $project = Join-Path $root 'src\QuietShield.App\QuietShield.App.csproj'
    $arguments = @('run', '--project', $project, '--configuration', $Configuration, '-p:Platform=x64', '--')
    if ($ApplicationArguments) {
        $arguments += $ApplicationArguments
    }
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList $arguments
}
finally {
    Stop-QuietShieldLog
}
