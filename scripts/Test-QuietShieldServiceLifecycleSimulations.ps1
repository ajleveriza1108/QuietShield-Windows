[CmdletBinding()]
param()
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'ServiceActivation.Script.Common.ps1')
. (Join-Path $PSScriptRoot 'QuietShieldService.Install.Common.ps1')
Assert-QuietShieldPowerShell51
Assert-QuietShieldNonElevated
$checks = [ordered]@{
    freshInstall = (Get-QuietShieldServiceLifecycleDisposition -ServiceCount 0 -OwnershipManifestPresent $false -ExactIdentityValid $false -Operation Install) -ceq 'FreshInstall'
    repeatedInstall = (Get-QuietShieldServiceLifecycleDisposition -ServiceCount 1 -OwnershipManifestPresent $true -ExactIdentityValid $true -Operation Install) -ceq 'AlreadyInstalled'
    orphanResume = (Get-QuietShieldServiceLifecycleDisposition -ServiceCount 0 -OwnershipManifestPresent $true -ExactIdentityValid $true -Operation Install) -ceq 'ResumeValidatedOrphan'
    foreignServiceRefusal = (Get-QuietShieldServiceLifecycleDisposition -ServiceCount 1 -OwnershipManifestPresent $false -ExactIdentityValid $false -Operation Install) -ceq 'RefuseForeignService'
    malformedOwnershipRefusal = (Get-QuietShieldServiceLifecycleDisposition -ServiceCount 1 -OwnershipManifestPresent $true -ExactIdentityValid $false -Operation Uninstall) -ceq 'RefuseForeignService'
    repeatedUninstall = (Get-QuietShieldServiceLifecycleDisposition -ServiceCount 0 -OwnershipManifestPresent $false -ExactIdentityValid $false -Operation Uninstall) -ceq 'AlreadyUninstalled'
    exactOwnedUninstall = (Get-QuietShieldServiceLifecycleDisposition -ServiceCount 1 -OwnershipManifestPresent $true -ExactIdentityValid $true -Operation Uninstall) -ceq 'UninstallExactOwnedServiceOnly'
    ambiguousIdentityRefusal = (Get-QuietShieldServiceLifecycleDisposition -ServiceCount 2 -OwnershipManifestPresent $true -ExactIdentityValid $true -Operation Install) -ceq 'RefuseAmbiguousServiceIdentity'
}
if (@($checks.GetEnumerator() | Where-Object { -not $_.Value }).Count -ne 0) { throw 'One or more exact service lifecycle simulations failed.' }
[pscustomobject]@{ status = 'Passed'; checks = $checks; windowsStateChanged = $false } | ConvertTo-Json -Depth 5
