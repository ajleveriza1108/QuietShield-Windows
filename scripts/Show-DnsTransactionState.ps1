[CmdletBinding()]
param(
    [string]$StatePath = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')

Assert-QuietShieldPowerShell51
$root = Get-QuietShieldRepositoryRoot
if ([string]::IsNullOrWhiteSpace($StatePath)) {
    $StatePath = Join-Path $root 'artifacts\dns-transaction\state.json'
}
$resolved = [System.IO.Path]::GetFullPath($StatePath)
if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
    [pscustomobject]@{
        schemaVersion = 1
        status = 'NotPrepared'
        statePath = $resolved
        message = 'No QuietShield DNS transaction state exists. Windows DNS has not been activated by this script.'
    } | ConvertTo-Json -Depth 4
    exit 0
}

try {
    $state = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
}
catch {
    throw ('The DNS transaction state JSON is malformed: ' + $_.Exception.Message)
}
if ([int]$state.schemaVersion -ne 1 -or [string]$state.productMarker -cne 'QuietShield' -or [string]$state.purpose -cne 'DnsTransactionState') {
    throw 'The DNS transaction state file is unknown or unsupported.'
}

[pscustomobject]@{
    schemaVersion = 1
    status = 'StateAvailable'
    statePath = $resolved
    transactionId = [string]$state.transactionId
    transactionState = [string]$state.state
    message = 'Read-only state display; no DNS or adapter command was invoked.'
} | ConvertTo-Json -Depth 4
