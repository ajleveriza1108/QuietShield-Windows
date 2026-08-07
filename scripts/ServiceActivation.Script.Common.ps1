Set-StrictMode -Version 2.0

$script:QuietShieldServiceName = 'QuietShieldService'
$script:QuietShieldServiceDisplayName = 'QuietShield Protection Service'
$script:QuietShieldServiceProductMarker = 'QuietShield'
$script:QuietShieldServicePurpose = 'Phase10BControlledServiceRehearsal'

function Test-QuietShieldSha256Text {
    param([string]$Value)
    return -not [string]::IsNullOrWhiteSpace($Value) -and $Value -match '\A[0-9A-Fa-f]{64}\z'
}

function Get-QuietShieldUtf8Sha256 {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace('-', '') }
    finally { $algorithm.Dispose() }
}

function Get-QuietShieldFileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.File]::OpenRead([IO.Path]::GetFullPath($Path))
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '') }
    finally { $algorithm.Dispose(); $stream.Dispose() }
}

function Get-QuietShieldApprovedProgramIdentity {
    param([Parameter(Mandatory = $true)][string]$Path)
    $canonicalPath = [IO.Path]::GetFullPath($Path).Trim().ToUpperInvariant()
    $hash = Get-QuietShieldUtf8Sha256 -Value $canonicalPath
    return 'windows-exe:' + $hash.Substring(0, 32).ToLowerInvariant()
}

function Get-QuietShieldServicePackagePayloadHash {
    param([Parameter(Mandatory = $true)]$Manifest)
    $lines = @()
    foreach ($file in @($Manifest.files | Sort-Object -Property relativePath)) {
        $lines += (([string]$file.relativePath) + '|' + ([string]$file.sha256).ToUpperInvariant() + '|' + [string][long]$file.length)
    }
    return Get-QuietShieldUtf8Sha256 -Value (([string][int]$Manifest.schemaVersion) + '|' + [string]$Manifest.productMarker + '|' + [string]$Manifest.purpose + '|' + [string]$Manifest.serviceName + "`n" + ($lines -join "`n"))
}

function Test-QuietShieldServicePackage {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$PackageRoot)
    $resolvedRoot = [IO.Path]::GetFullPath($PackageRoot).TrimEnd('\')
    $manifestPath = Join-Path $resolvedRoot 'service-package-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'The QuietShield service package manifest is missing.' }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ([int]$manifest.schemaVersion -ne 1 -or [string]$manifest.productMarker -cne $script:QuietShieldServiceProductMarker -or
        [string]$manifest.purpose -cne 'QuietShieldServicePackage' -or [string]$manifest.serviceName -cne $script:QuietShieldServiceName) { throw 'The service package manifest identity is invalid.' }
    $expected = @($manifest.files)
    if ($expected.Count -eq 0) { throw 'The service package manifest has no files.' }
    foreach ($entry in $expected) {
        $relative = [string]$entry.relativePath
        if ([string]::IsNullOrWhiteSpace($relative) -or [IO.Path]::IsPathRooted($relative) -or $relative.Contains('..')) { throw 'The service package contains an unsafe relative path.' }
        $path = Join-Path $resolvedRoot $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ('A service package file is missing: ' + $relative) }
        $actualHash = Get-QuietShieldFileSha256 -Path $path
        if ($actualHash -cne ([string]$entry.sha256).ToUpperInvariant() -or (Get-Item -LiteralPath $path).Length -ne [long]$entry.length) { throw ('A service package file failed validation: ' + $relative) }
    }
    $actualRelativeFiles = @(Get-ChildItem -LiteralPath $resolvedRoot -File -Recurse | Where-Object { $_.FullName -cne $manifestPath } | ForEach-Object { $_.FullName.Substring($resolvedRoot.Length + 1).Replace('\','/') } | Sort-Object)
    $expectedRelativeFiles = @($expected | ForEach-Object { ([string]$_.relativePath).Replace('\','/') } | Sort-Object)
    if (($actualRelativeFiles -join '|') -cne ($expectedRelativeFiles -join '|')) { throw 'The service package contains missing or unexpected files.' }
    $payloadHash = Get-QuietShieldServicePackagePayloadHash -Manifest $manifest
    if (-not (Test-QuietShieldSha256Text -Value ([string]$manifest.payloadSha256)) -or $payloadHash -cne ([string]$manifest.payloadSha256).ToUpperInvariant()) { throw 'The service package payload hash is invalid.' }
    $serviceExecutable = Join-Path $resolvedRoot 'QuietShield.Service.exe'
    if (-not (Test-Path -LiteralPath $serviceExecutable -PathType Leaf)) { throw 'The validated service executable is missing.' }
    return [pscustomobject]@{ Root = $resolvedRoot; Manifest = $manifest; ManifestPath = $manifestPath; ExecutablePath = $serviceExecutable; PayloadSha256 = $payloadHash }
}

function Get-QuietShieldServiceActivationPayloadHash {
    param([Parameter(Mandatory = $true)]$Configuration)
    $canonical = @(
        [string][int]$Configuration.schemaVersion, [string]$Configuration.productMarker, [string]$Configuration.purpose,
        [string]$Configuration.serviceName, ([Guid][string]$Configuration.approvedRehearsalId).ToString('D'), [string]$Configuration.authorizedUserSid,
        [IO.Path]::GetFullPath([string]$Configuration.probePath), ([string]$Configuration.probeSha256).ToUpperInvariant(),
        [IO.Path]::GetFullPath([string]$Configuration.enforcementScriptPath), ([string]$Configuration.enforcementScriptSha256).ToUpperInvariant(),
        ([DateTimeOffset]$Configuration.createdAtUtc).ToUniversalTime().ToString('O'), ([DateTimeOffset]$Configuration.expiresAtUtc).ToUniversalTime().ToString('O')
    ) -join '|'
    return Get-QuietShieldUtf8Sha256 -Value $canonical
}

function Test-QuietShieldServiceActivationConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path, [switch]$AllowExpired)
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw 'The service activation configuration is missing.' }
    $configuration = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
    if ([int]$configuration.schemaVersion -ne 1 -or [string]$configuration.productMarker -cne $script:QuietShieldServiceProductMarker -or
        [string]$configuration.purpose -cne $script:QuietShieldServicePurpose -or [string]$configuration.serviceName -cne $script:QuietShieldServiceName) { throw 'The service activation configuration identity is invalid.' }
    if ([Guid][string]$configuration.approvedRehearsalId -eq [Guid]::Empty) { throw 'The approved rehearsal ID is invalid.' }
    if ([string]$configuration.authorizedUserSid -notmatch '\AS-1-') { throw 'The authorized user SID is invalid.' }
    foreach ($pair in @(@([string]$configuration.probePath,[string]$configuration.probeSha256), @([string]$configuration.enforcementScriptPath,[string]$configuration.enforcementScriptSha256))) {
        if (-not (Test-Path -LiteralPath $pair[0] -PathType Leaf) -or -not (Test-QuietShieldSha256Text -Value $pair[1])) { throw 'An approved activation file is missing or has an invalid hash.' }
        if ((Get-QuietShieldFileSha256 -Path $pair[0]) -cne $pair[1].ToUpperInvariant()) { throw 'An approved activation file hash does not match.' }
    }
    $created = ([DateTimeOffset]$configuration.createdAtUtc).ToUniversalTime()
    $expires = ([DateTimeOffset]$configuration.expiresAtUtc).ToUniversalTime()
    if ($expires -le $created -or ($expires - $created).TotalHours -gt 4) { throw 'The activation validity window is invalid.' }
    if (-not $AllowExpired -and ([DateTimeOffset]::UtcNow -lt $created.AddMinutes(-5) -or [DateTimeOffset]::UtcNow -ge $expires)) { throw 'The activation configuration is not currently valid.' }
    $payloadHash = Get-QuietShieldServiceActivationPayloadHash -Configuration $configuration
    if ($payloadHash -cne ([string]$configuration.payloadSha256).ToUpperInvariant()) { throw 'The activation configuration payload hash is invalid.' }
    return [pscustomobject]@{ Path = $resolved; Configuration = $configuration; PayloadSha256 = $payloadHash }
}

function Get-QuietShieldFirewallTransactionPayloadHash {
    param([Parameter(Mandatory = $true)]$Transaction)
    $backup = 'absent'
    if ($null -ne $Transaction.backupRule) {
        $backup = @([string]$Transaction.backupRule.ownershipMarker, [string][int]$Transaction.backupRule.schemaVersion,
            [string]$Transaction.backupRule.name, [string]$Transaction.backupRule.description, [IO.Path]::GetFullPath([string]$Transaction.backupRule.programPath),
            ([bool]$Transaction.backupRule.enabled).ToString(), [string]$Transaction.backupRule.direction, [string]$Transaction.backupRule.action,
            [string]$Transaction.backupRule.profile, [string]$Transaction.backupRule.protocol, [string]$Transaction.backupRule.remoteAddress,
            [string][int]$Transaction.backupRule.remotePort) -join '~'
    }
    $exemptions = @($Transaction.safetyExemptions | ForEach-Object { ([string]$_.kind) + ':' + ([string]$_.visibleReason) }) -join '~'
    $canonical = @([string][int]$Transaction.schemaVersion, [string]$Transaction.productMarker, [string]$Transaction.purpose,
        ([Guid][string]$Transaction.transactionId).ToString('D'), ([Guid][string]$Transaction.approvedRehearsalId).ToString('D'),
        ([DateTimeOffset]$Transaction.createdAtUtc).ToUniversalTime().ToString('O'), [string]$Transaction.stage, [string]$Transaction.profileId,
        [string]$Transaction.stableApplicationIdentity, [IO.Path]::GetFullPath([string]$Transaction.programPath), ([string]$Transaction.programSha256).ToUpperInvariant(),
        [string]$Transaction.policy, ([string]$Transaction.stableRuleId).ToLowerInvariant(), [string]$Transaction.ruleName, [string]$Transaction.description,
        $backup, $exemptions) -join '|'
    return Get-QuietShieldUtf8Sha256 -Value $canonical
}

function Test-QuietShieldFirewallTransaction {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw 'The persistent Firewall transaction is missing.' }
    $transaction = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
    if ([int]$transaction.schemaVersion -ne 1 -or [string]$transaction.productMarker -cne $script:QuietShieldServiceProductMarker -or [string]$transaction.purpose -cne $script:QuietShieldServicePurpose) { throw 'The persistent Firewall transaction identity is foreign.' }
    if ([string]$transaction.policy -cnotin @('Blocked','AllowedOnAll')) { throw 'Only Blocked and AllowedOnAll transactions are supported.' }
    if ([string]$transaction.ruleName -cne ('QuietShield.ProgramLock.' + [string]$transaction.stableRuleId)) { throw 'The deterministic exact rule name is invalid.' }
    if ([string]$transaction.stableRuleId -notmatch '\A[0-9a-f]{32}\z') { throw 'The deterministic rule ID is invalid.' }
    if ([string]$transaction.description -notmatch '\A[\x20-\x7E]{1,160}\z') { throw 'The exact rule description is invalid.' }
    if (-not (Test-Path -LiteralPath ([string]$transaction.programPath) -PathType Leaf) -or (Get-QuietShieldFileSha256 -Path ([string]$transaction.programPath)) -cne ([string]$transaction.programSha256).ToUpperInvariant()) { throw 'The exact transaction program identity is invalid.' }
    if ($null -ne $transaction.backupRule -and ([string]$transaction.backupRule.ownershipMarker -cne 'QuietShield' -or [string]$transaction.backupRule.name -cne [string]$transaction.ruleName)) { throw 'The backed-up rule identity is foreign or mismatched.' }
    if (@($transaction.safetyExemptions).Count -ne 8) { throw 'The transaction safety exemptions are incomplete.' }
    $payloadHash = Get-QuietShieldFirewallTransactionPayloadHash -Transaction $transaction
    if ($payloadHash -cne ([string]$transaction.payloadSha256).ToUpperInvariant()) { throw 'The persistent Firewall transaction payload hash is invalid.' }
    return [pscustomobject]@{ Path = $resolved; Transaction = $transaction; PayloadSha256 = $payloadHash }
}

function Get-QuietShieldExactService {
    return @(Get-CimInstance -ClassName Win32_Service -Filter "Name='QuietShieldService'" -ErrorAction SilentlyContinue)
}
