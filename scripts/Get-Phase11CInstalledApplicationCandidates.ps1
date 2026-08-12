[CmdletBinding()]
param(
    [string]$OutputPath = 'D:\QuietShield-Phase11-Work\PHASE11C-CANDIDATES.json'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ServiceActivation.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'Phase11C.InstalledApp.Common.ps1')

Assert-QuietShieldPowerShell51

$workingDirectory = Join-Path ([IO.Path]::GetDirectoryName($OutputPath)) 'phase11c-candidate-probes'
New-Item -ItemType Directory -Path $workingDirectory -Force | Out-Null

try {
    $candidates = @(Get-Phase11CInstalledApplicationCandidates -WorkingDirectory $workingDirectory)
    $ready = @($candidates | Where-Object { [bool]$_.networkProbePassed })

    [pscustomobject][ordered]@{
        schemaVersion = 1
        status = 'Passed'
        candidateCount = $candidates.Count
        readyCandidateCount = $ready.Count
        candidates = $candidates
    } | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $OutputPath -Encoding UTF8

    Get-Content -LiteralPath $OutputPath -Raw
}
finally {
    Remove-Item -LiteralPath $workingDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
