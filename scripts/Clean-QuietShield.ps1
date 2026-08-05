[CmdletBinding(SupportsShouldProcess = $true)]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')

Assert-QuietShieldPowerShell51
Assert-QuietShieldNonElevated
$logPath = Start-QuietShieldLog -Name 'clean'

try {
    $root = Get-QuietShieldRepositoryRoot
    $artifacts = Join-Path $root 'artifacts'
    $recognizedNames = @('bin', 'obj', 'test-results', 'packages', 'dotnet-home', 'smoke')

    foreach ($name in $recognizedNames) {
        $target = Join-Path $artifacts $name
        $fullTarget = [System.IO.Path]::GetFullPath($target)
        $fullArtifacts = [System.IO.Path]::GetFullPath($artifacts)

        if (-not $fullTarget.StartsWith($fullArtifacts + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw ("Refusing unsafe clean target: {0}" -f $fullTarget)
        }

        if (Test-Path -LiteralPath $fullTarget) {
            if ($PSCmdlet.ShouldProcess($fullTarget, 'Remove recognized generated QuietShield build output')) {
                Remove-Item -LiteralPath $fullTarget -Recurse -Force
                Write-Output ("Removed generated output: {0}" -f $fullTarget)
            }
        }
    }
}
finally {
    Stop-QuietShieldLog
}
