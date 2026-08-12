[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')

Assert-QuietShieldPowerShell51
$Checks = [ordered]@{
    exactRequestedPatchAccepted = Test-QuietShieldDotNetSdkCompatibility -RequestedVersion '10.0.302' -ResolvedVersion '10.0.302' -RollForward 'latestPatch' -AllowPrerelease $false
    laterSameFeatureBandPatchAccepted = Test-QuietShieldDotNetSdkCompatibility -RequestedVersion '10.0.302' -ResolvedVersion '10.0.303' -RollForward 'latestPatch' -AllowPrerelease $false
    earlierPatchRejected = -not (Test-QuietShieldDotNetSdkCompatibility -RequestedVersion '10.0.302' -ResolvedVersion '10.0.301' -RollForward 'latestPatch' -AllowPrerelease $false)
    nextFeatureBandRejected = -not (Test-QuietShieldDotNetSdkCompatibility -RequestedVersion '10.0.302' -ResolvedVersion '10.0.400' -RollForward 'latestPatch' -AllowPrerelease $false)
    prereleaseRejected = -not (Test-QuietShieldDotNetSdkCompatibility -RequestedVersion '10.0.302' -ResolvedVersion '10.0.303-preview.1' -RollForward 'latestPatch' -AllowPrerelease $false)
    differentRollForwardPolicyRejected = -not (Test-QuietShieldDotNetSdkCompatibility -RequestedVersion '10.0.302' -ResolvedVersion '10.0.303' -RollForward 'latestFeature' -AllowPrerelease $false)
    visualStudioBaselinePatchAccepted = Test-QuietShieldVisualStudioCompatibility -RequiredFeatureLine '18.8' -MinimumServicingVersion '18.8.2' -ResolvedProductVersion '18.8.2' -InstallationVersion '18.8.12023.21' -IsComplete $true -IsLaunchable $true -IsPrerelease $false
    visualStudioNewerServicingPatchAccepted = Test-QuietShieldVisualStudioCompatibility -RequiredFeatureLine '18.8' -MinimumServicingVersion '18.8.2' -ResolvedProductVersion '18.8.3' -InstallationVersion '18.8.12105.206' -IsComplete $true -IsLaunchable $true -IsPrerelease $false
    visualStudioOlderServicingPatchRejected = -not (Test-QuietShieldVisualStudioCompatibility -RequiredFeatureLine '18.8' -MinimumServicingVersion '18.8.2' -ResolvedProductVersion '18.8.1' -InstallationVersion '18.8.11900.1' -IsComplete $true -IsLaunchable $true -IsPrerelease $false)
    visualStudioDifferentFeatureLineRejected = -not (Test-QuietShieldVisualStudioCompatibility -RequiredFeatureLine '18.8' -MinimumServicingVersion '18.8.2' -ResolvedProductVersion '18.9.0' -InstallationVersion '18.9.10000.1' -IsComplete $true -IsLaunchable $true -IsPrerelease $false)
    visualStudioIncompleteRejected = -not (Test-QuietShieldVisualStudioCompatibility -RequiredFeatureLine '18.8' -MinimumServicingVersion '18.8.2' -ResolvedProductVersion '18.8.3' -InstallationVersion '18.8.12105.206' -IsComplete $false -IsLaunchable $true -IsPrerelease $false)
    visualStudioUnlaunchableRejected = -not (Test-QuietShieldVisualStudioCompatibility -RequiredFeatureLine '18.8' -MinimumServicingVersion '18.8.2' -ResolvedProductVersion '18.8.3' -InstallationVersion '18.8.12105.206' -IsComplete $true -IsLaunchable $false -IsPrerelease $false)
    visualStudioPrereleaseRejected = -not (Test-QuietShieldVisualStudioCompatibility -RequiredFeatureLine '18.8' -MinimumServicingVersion '18.8.2' -ResolvedProductVersion '18.8.3-preview.1' -InstallationVersion '18.8.12105.206' -IsComplete $true -IsLaunchable $true -IsPrerelease $true)
}
if (@($Checks.GetEnumerator() | Where-Object { -not $_.Value }).Count -ne 0) { throw 'One or more capability-based toolchain compatibility checks failed.' }
$ActualToolchain = @(Assert-QuietShieldToolchain)
[pscustomobject]@{ status = 'Passed'; checks = $Checks; actualToolchain = $ActualToolchain } | ConvertTo-Json -Depth 5
