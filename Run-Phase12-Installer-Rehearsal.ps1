[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ExpectedApproval = 'APPROVE PHASE 12 INSTALLER REHEARSAL'
$script:ExpectedBranch = 'feature/phase-12-self-contained-beta-installer'
$script:ExpectedHead = 'a75bbd5f4e0bef24501cbc42f6b74f47875a34d7'
$script:ExpectedMain = '3ae8b328aaa40cb3b037a56ce59bce649a26ba90'
$script:ExpectedPackageSource = '3ae8b328aaa40cb3b037a56ce59bce649a26ba90'
$script:ExpectedVersion = '0.12.0-beta.1'
$script:ExpectedInstallerHash = 'B065D823F657D3E780795C5D686E7E83B6F7D2638EC3DCA3E8EC04538304ED64'
$script:InstallerAppId = '{6D13D40D-0A66-49F7-A422-235A2B89DA61}'
$script:UninstallKeyName = $script:InstallerAppId + '_is1'
$script:RepositoryRoot = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\')
$script:ArtifactRoot = Join-Path $script:RepositoryRoot ('artifacts\installer\' + $script:ExpectedVersion)
$script:InstallerPath = Join-Path $script:ArtifactRoot ('package\QuietShield-Windows-x64-' + $script:ExpectedVersion + '.exe')
$script:PackageManifestPath = Join-Path $script:ArtifactRoot 'phase12-package-manifest.json'
$script:PackageValidationPath = Join-Path $script:ArtifactRoot 'phase12-validation.json'
$script:WorkRoot = 'D:\QuietShield-Phase12-Work'
$script:ResultPath = Join-Path $script:WorkRoot 'PHASE12-INSTALLER-REHEARSAL-RESULT.txt'
$script:ProductRoot = [IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'QuietShield')).TrimEnd('\')
$script:StateRoot = [IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'QuietShield\Service')).TrimEnd('\')
$script:UserDataRoot = [IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) 'QuietShield')).TrimEnd('\')
$script:AttemptRoot = $null
$script:NativeSequence = 0
$script:TimedOutProcessId = $null
$script:ForwardChangeStarted = $false
$script:TranscriptStarted = $false
$script:LockStream = $null
$script:Result = [ordered]@{
    Status = 'Not started'
    InstallerSha = $script:ExpectedInstallerHash
    FreshInstall = 'Not attempted'
    ServiceRegistrationStart = 'Not attempted'
    IpcAppStartup = 'Not attempted'
    ProgramLockRulesAfterInstall = 'Not measured'
    DnsComparison = 'Not measured'
    ReinstallUpgradeResult = 'Not attempted'
    UninstallResult = 'Not attempted'
    ServiceResidue = 'Not measured'
    InstallRootResidue = 'Not measured'
    UninstallRegistrationResidue = 'Not measured'
    ProgramLockRuleResidue = 'Not measured'
    ProtectedStateComparison = 'Not measured'
    RestartRequired = 'NO'
    SystemChanges = 'No Windows changes started'
    UpgradeActuallyProven = 'NO'
    CleanupRequired = 'NO'
    Failure = ''
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    try {
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '') }
        finally { $algorithm.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Get-Utf8Sha256 {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    $encoding = New-Object Text.UTF8Encoding($false)
    $bytes = $encoding.GetBytes($Value)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '') }
    finally { $algorithm.Dispose() }
}

function ConvertTo-NativeArgument {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    if ($Value.IndexOf([char]0) -ge 0 -or $Value.Contains("`r") -or $Value.Contains("`n") -or $Value.Contains('"')) {
        throw 'A native process argument contains an unsupported character.'
    }
    if ($Value.Length -eq 0) { return '""' }
    if ($Value -notmatch '\s') { return $Value }
    return '"' + $Value + '"'
}

function Invoke-NativeProcessCore {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Arguments,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][int[]]$AllowedExitCodes,
        [string]$LogLabel = '',
        [switch]$PersistOutput
    )
    $startInfo = New-Object Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = (@($Arguments | ForEach-Object { ConvertTo-NativeArgument -Value ([string]$_) }) -join ' ')
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw ('Could not start native process: ' + $FilePath) }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        $script:TimedOutProcessId = $process.Id
        throw ('Native process did not exit within the bounded timeout. It was not terminated. PID requiring review: ' + [string]$process.Id)
    }
    $process.WaitForExit()
    $process.Refresh()
    if (-not $process.HasExited) { throw ('Native process exit could not be confirmed. PID: ' + [string]$process.Id) }
    $stdoutText = $stdoutTask.GetAwaiter().GetResult()
    $stderrText = $stderrTask.GetAwaiter().GetResult()
    $exitCode = $process.ExitCode
    $process.Dispose()
    if ($PersistOutput) {
        if ([string]::IsNullOrWhiteSpace($script:AttemptRoot)) { throw 'The evidence directory is unavailable.' }
        $script:NativeSequence++
        $safeLabel = ($LogLabel -replace '[^0-9A-Za-z._-]', '_')
        $prefix = ('{0:D3}-{1}' -f $script:NativeSequence, $safeLabel)
        Set-Content -LiteralPath (Join-Path $script:AttemptRoot ($prefix + '.stdout.log')) -Value $stdoutText -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $script:AttemptRoot ($prefix + '.stderr.log')) -Value $stderrText -Encoding UTF8
        [pscustomobject][ordered]@{ filePath = $FilePath; arguments = $Arguments; exitCode = $exitCode; completedAtUtc = [DateTimeOffset]::UtcNow.ToString('O') } |
            ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $script:AttemptRoot ($prefix + '.process.json')) -Encoding UTF8
    }
    if ($exitCode -notin $AllowedExitCodes) {
        throw ('Native process failed with exit code ' + [string]$exitCode + ': ' + $FilePath)
    }
    return [pscustomobject]@{ ExitCode = $exitCode; StdOut = $stdoutText; StdErr = $stderrText }
}

function Invoke-ReadOnlyNativeProcess {
    param([string]$FilePath, [string[]]$Arguments, [int]$TimeoutSeconds = 30)
    return Invoke-NativeProcessCore -FilePath $FilePath -Arguments $Arguments -TimeoutSeconds $TimeoutSeconds -AllowedExitCodes @(0)
}

function Invoke-LoggedNativeProcess {
    param([string]$FilePath, [string[]]$Arguments, [string]$LogLabel, [int]$TimeoutSeconds = 600)
    return Invoke-NativeProcessCore -FilePath $FilePath -Arguments $Arguments -TimeoutSeconds $TimeoutSeconds -AllowedExitCodes @(0) -LogLabel $LogLabel -PersistOutput
}

function Write-ResultFile {
    if (-not (Test-Path -LiteralPath $script:WorkRoot -PathType Container)) { return }
    $lines = @(
        'STATUS: ' + [string]$script:Result.Status,
        'installer SHA: ' + [string]$script:Result.InstallerSha,
        'fresh install: ' + [string]$script:Result.FreshInstall,
        'service registration/start: ' + [string]$script:Result.ServiceRegistrationStart,
        'IPC/app startup: ' + [string]$script:Result.IpcAppStartup,
        'Program Lock rules after install: ' + [string]$script:Result.ProgramLockRulesAfterInstall,
        'DNS comparison: ' + [string]$script:Result.DnsComparison,
        'reinstall/upgrade result: ' + [string]$script:Result.ReinstallUpgradeResult,
        'uninstall result: ' + [string]$script:Result.UninstallResult,
        'service residue: ' + [string]$script:Result.ServiceResidue,
        'install-root residue: ' + [string]$script:Result.InstallRootResidue,
        'uninstall-registration residue: ' + [string]$script:Result.UninstallRegistrationResidue,
        'Program Lock rule residue: ' + [string]$script:Result.ProgramLockRuleResidue,
        'protected-state comparison: ' + [string]$script:Result.ProtectedStateComparison,
        'restart required: ' + [string]$script:Result.RestartRequired,
        'system changes: ' + [string]$script:Result.SystemChanges,
        'upgrade actually proven: ' + [string]$script:Result.UpgradeActuallyProven,
        'cleanup required: ' + [string]$script:Result.CleanupRequired
    )
    if (-not [string]::IsNullOrWhiteSpace([string]$script:Result.Failure)) { $lines += 'failure: ' + [string]$script:Result.Failure }
    Set-Content -LiteralPath $script:ResultPath -Value $lines -Encoding UTF8
}

function Write-Checkpoint {
    param([Parameter(Mandatory = $true)][string]$Stage)
    if ([string]::IsNullOrWhiteSpace($script:AttemptRoot)) { return }
    [pscustomobject][ordered]@{
        schemaVersion = 1
        productMarker = 'QuietShield'
        purpose = 'Phase12InstallerRehearsalCheckpoint'
        stage = $Stage
        updatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        result = $script:Result
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $script:AttemptRoot 'checkpoint.json') -Encoding UTF8
    Write-ResultFile
}

function Get-RegistryValueData {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [byte[]]) { return [Convert]::ToBase64String($Value) }
    if ($Value -is [string[]]) { return @($Value) }
    return [string]$Value
}

function Get-RegistrySnapshotData {
    param([Parameter(Mandatory = $true)][string[]]$Paths)
    $rows = @()
    foreach ($registryPath in @($Paths | Sort-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $registryPath)) {
            $rows += [pscustomobject][ordered]@{ Path = $registryPath; Exists = $false; Values = @() }
            continue
        }
        $registryKey = Get-Item -LiteralPath $registryPath -ErrorAction Stop
        $values = @()
        foreach ($valueName in @($registryKey.GetValueNames() | Sort-Object)) {
            $displayName = $valueName
            if ([string]::IsNullOrEmpty($displayName)) { $displayName = '(Default)' }
            $values += [pscustomobject][ordered]@{
                Name = $displayName
                Kind = [string]$registryKey.GetValueKind($valueName)
                Value = Get-RegistryValueData -Value $registryKey.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
        }
        $rows += [pscustomobject][ordered]@{ Path = $registryPath; Exists = $true; Values = $values }
        $registryKey.Close()
    }
    return @($rows)
}

function Get-ExactUninstallRegistrations {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $registrations = @()
    foreach ($rootPath in $roots) {
        $keyPath = Join-Path $rootPath $script:UninstallKeyName
        if (Test-Path -LiteralPath $keyPath) {
            $item = Get-ItemProperty -LiteralPath $keyPath -ErrorAction Stop
            $registrations += [pscustomobject][ordered]@{
                KeyPath = $keyPath
                DisplayName = [string]$item.DisplayName
                DisplayVersion = [string]$item.DisplayVersion
                InstallLocation = [string]$item.InstallLocation
                UninstallString = [string]$item.UninstallString
                QuietUninstallString = [string]$item.QuietUninstallString
            }
        }
    }
    return @($registrations)
}

function Get-AllQuietShieldUninstallRegistrations {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $registrations = @()
    foreach ($rootPath in $roots) {
        if (-not (Test-Path -LiteralPath $rootPath)) { continue }
        foreach ($key in @(Get-ChildItem -LiteralPath $rootPath -ErrorAction Stop)) {
            $item = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
            if ([string]$item.DisplayName -like 'QuietShield*' -or $key.PSChildName -ceq $script:UninstallKeyName) {
                $registrations += [pscustomobject][ordered]@{ KeyPath = $key.Name; KeyName = $key.PSChildName; DisplayName = [string]$item.DisplayName; DisplayVersion = [string]$item.DisplayVersion }
            }
        }
    }
    return @($registrations | Sort-Object -Property KeyPath)
}

function Get-ProgramLockRuleCount {
    return @(Get-NetFirewallRule -Name 'QuietShield.ProgramLock.*' -ErrorAction SilentlyContinue).Count
}

function Get-DirectoryInventory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return @() }
    $rootPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $rows = @()
    foreach ($file in @(Get-ChildItem -LiteralPath $rootPath -File -Recurse -ErrorAction Stop | Sort-Object -Property FullName)) {
        $rows += [pscustomobject][ordered]@{
            RelativePath = $file.FullName.Substring($rootPath.Length + 1).Replace('\', '/')
            Length = [long]$file.Length
            Sha256 = Get-FileSha256 -Path $file.FullName
        }
    }
    return @($rows)
}

function Get-PersistentFirewallData {
    $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
    $ruleRows = @($rules | Select-Object Name, DisplayName, Description, Group, Enabled, Profile, Platform, Direction, Action, EdgeTraversalPolicy, LooseSourceMapping, LocalOnlyMapping, Owner | Sort-Object -Property Name)
    $applicationRows = @()
    $portRows = @()
    $addressRows = @()
    $serviceRows = @()
    $interfaceRows = @()
    if ($rules.Count -ne 0) {
        $applicationRows = @($rules | Get-NetFirewallApplicationFilter -ErrorAction Stop | Select-Object InstanceID, Program, Package | Sort-Object -Property InstanceID)
        $portRows = @($rules | Get-NetFirewallPortFilter -ErrorAction Stop | Select-Object InstanceID, Protocol, LocalPort, RemotePort, IcmpType, DynamicTarget | Sort-Object -Property InstanceID)
        $addressRows = @($rules | Get-NetFirewallAddressFilter -ErrorAction Stop | Select-Object InstanceID, LocalAddress, RemoteAddress | Sort-Object -Property InstanceID)
        $serviceRows = @($rules | Get-NetFirewallServiceFilter -ErrorAction Stop | Select-Object InstanceID, Service | Sort-Object -Property InstanceID)
        $interfaceRows = @($rules | Get-NetFirewallInterfaceFilter -ErrorAction Stop | Select-Object InstanceID, InterfaceAlias | Sort-Object -Property InstanceID)
    }
    return [pscustomobject][ordered]@{ Rules = $ruleRows; ApplicationFilters = $applicationRows; PortFilters = $portRows; AddressFilters = $addressRows; ServiceFilters = $serviceRows; InterfaceFilters = $interfaceRows }
}

function Get-ProtectedSnapshot {
    $firewallProfiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, AllowLocalFirewallRules | Sort-Object -Property Name)
    $firewallData = Get-PersistentFirewallData
    $quietShieldRules = @(Get-NetFirewallRule -Name 'QuietShield.*' -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, Description, Enabled, Direction, Action, Profile | Sort-Object -Property Name)
    $dnsRows = @()
    foreach ($dnsRow in @(Get-DnsClientServerAddress -ErrorAction Stop | Sort-Object -Property InterfaceIndex, AddressFamily)) {
        $dnsRows += [pscustomobject][ordered]@{ InterfaceIndex = [int]$dnsRow.InterfaceIndex; InterfaceAlias = [string]$dnsRow.InterfaceAlias; AddressFamily = [int]$dnsRow.AddressFamily; ServerAddresses = @($dnsRow.ServerAddresses | ForEach-Object { [string]$_ }) }
    }
    $adapterIdentity = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Select-Object InterfaceGuid, InterfaceIndex, Name, InterfaceDescription, MacAddress, PhysicalMediaType, HardwareInterface | Sort-Object -Property InterfaceGuid, InterfaceIndex)
    $adapterOperational = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Select-Object InterfaceGuid, InterfaceIndex, Name, Status | Sort-Object -Property InterfaceGuid, InterfaceIndex)
    $adapterConfiguration = @(Get-NetIPInterface -ErrorAction Stop | Select-Object InterfaceIndex, InterfaceAlias, AddressFamily, Dhcp, RouterDiscovery, NlMtu, AutomaticMetric, InterfaceMetric, WeakHostSend, WeakHostReceive, Forwarding, Advertising | Sort-Object -Property InterfaceIndex, AddressFamily)
    $startupPaths = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')
    $startupRows = @()
    foreach ($startupPath in $startupPaths) {
        if (-not (Test-Path -LiteralPath $startupPath)) { continue }
        $startupItem = Get-ItemProperty -LiteralPath $startupPath -ErrorAction Stop
        foreach ($property in @($startupItem.PSObject.Properties | Where-Object { $_.Name -like 'QuietShield*' } | Sort-Object -Property Name)) {
            $startupRows += [pscustomobject][ordered]@{ Path = $startupPath; Name = $property.Name; Value = [string]$property.Value }
        }
    }
    $wfpPaths = @(
        'HKLM:\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\Persistent\Provider\{F79D8C43-A343-4A05-BF03-4DA61BDF8498}',
        'HKLM:\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\Persistent\SubLayer\{5D56C870-CF61-4BA7-B59E-89B4B2364A03}',
        'HKLM:\SYSTEM\CurrentControlSet\Services\QuietShieldWfpCallout',
        'HKLM:\SYSTEM\CurrentControlSet\Services\QuietShield.Callout',
        'HKLM:\SYSTEM\CurrentControlSet\Services\QuietShieldDriver'
    )
    $quietShieldRegistryPaths = @(
        'HKCU:\Software\QuietShield',
        'HKLM:\Software\QuietShield',
        'HKLM:\Software\WOW6432Node\QuietShield',
        'HKLM:\SYSTEM\CurrentControlSet\Services\QuietShield',
        'HKLM:\SYSTEM\CurrentControlSet\Services\QuietShield.Service'
    )
    $serviceRegistryPaths = @('HKLM:\SYSTEM\CurrentControlSet\Services\QuietShieldService')
    $pendingRename = Get-RegistrySnapshotData -Paths @('HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager')
    $snapshot = [ordered]@{
        CapturedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        FirewallProfiles = $firewallProfiles
        PersistentFirewall = $firewallData
        QuietShieldFirewallRules = $quietShieldRules
        Dns = $dnsRows
        AdapterIdentity = $adapterIdentity
        AdapterConfiguration = $adapterConfiguration
        AdapterOperational = $adapterOperational
        Startup = $startupRows
        QuietShieldWfp = Get-RegistrySnapshotData -Paths $wfpPaths
        QuietShieldRegistry = Get-RegistrySnapshotData -Paths $quietShieldRegistryPaths
        QuietShieldServiceRegistry = Get-RegistrySnapshotData -Paths $serviceRegistryPaths
        PendingRenameOperations = @($pendingRename | ForEach-Object {
            $values = @($_.Values | Where-Object { $_.Name -eq 'PendingFileRenameOperations' })
            [pscustomobject][ordered]@{ Path = $_.Path; Exists = ($values.Count -ne 0); Values = $values }
        })
    }
    return [pscustomobject][ordered]@{
        CapturedAtUtc = $snapshot.CapturedAtUtc
        FirewallProfilesHash = Get-Utf8Sha256 -Value (($snapshot.FirewallProfiles | ConvertTo-Json -Depth 8 -Compress) -join '')
        PersistentFirewallHash = Get-Utf8Sha256 -Value (($snapshot.PersistentFirewall | ConvertTo-Json -Depth 12 -Compress) -join '')
        QuietShieldFirewallHash = Get-Utf8Sha256 -Value (($snapshot.QuietShieldFirewallRules | ConvertTo-Json -Depth 8 -Compress) -join '')
        DnsHash = Get-Utf8Sha256 -Value (($snapshot.Dns | ConvertTo-Json -Depth 8 -Compress) -join '')
        AdapterIdentityHash = Get-Utf8Sha256 -Value (($snapshot.AdapterIdentity | ConvertTo-Json -Depth 8 -Compress) -join '')
        AdapterConfigurationHash = Get-Utf8Sha256 -Value (($snapshot.AdapterConfiguration | ConvertTo-Json -Depth 8 -Compress) -join '')
        AdapterOperationalHash = Get-Utf8Sha256 -Value (($snapshot.AdapterOperational | ConvertTo-Json -Depth 8 -Compress) -join '')
        StartupHash = Get-Utf8Sha256 -Value (($snapshot.Startup | ConvertTo-Json -Depth 8 -Compress) -join '')
        QuietShieldWfpHash = Get-Utf8Sha256 -Value (($snapshot.QuietShieldWfp | ConvertTo-Json -Depth 8 -Compress) -join '')
        QuietShieldRegistryHash = Get-Utf8Sha256 -Value (($snapshot.QuietShieldRegistry | ConvertTo-Json -Depth 8 -Compress) -join '')
        QuietShieldServiceRegistryHash = Get-Utf8Sha256 -Value (($snapshot.QuietShieldServiceRegistry | ConvertTo-Json -Depth 8 -Compress) -join '')
        PendingRenameHash = Get-Utf8Sha256 -Value (($snapshot.PendingRenameOperations | ConvertTo-Json -Depth 8 -Compress) -join '')
        Data = [pscustomobject]$snapshot
    }
}

function Compare-ProtectedSnapshot {
    param([Parameter(Mandatory = $true)]$Before, [Parameter(Mandatory = $true)]$After, [switch]$IncludeServiceAndRestart)
    $properties = @('FirewallProfilesHash','PersistentFirewallHash','QuietShieldFirewallHash','DnsHash','AdapterIdentityHash','AdapterConfigurationHash','StartupHash','QuietShieldWfpHash','QuietShieldRegistryHash')
    if ($IncludeServiceAndRestart) { $properties += @('QuietShieldServiceRegistryHash','PendingRenameHash') }
    $differences = @()
    foreach ($propertyName in $properties) {
        if ([string]$Before.$propertyName -cne [string]$After.$propertyName) { $differences += $propertyName }
    }
    return [pscustomobject][ordered]@{
        Match = ($differences.Count -eq 0)
        Differences = $differences
        AdapterOperationalChanged = ([string]$Before.AdapterOperationalHash -cne [string]$After.AdapterOperationalHash)
    }
}

function Save-Snapshot {
    param([Parameter(Mandatory = $true)]$Snapshot, [Parameter(Mandatory = $true)][string]$Name)
    $Snapshot | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath (Join-Path $script:AttemptRoot ($Name + '.json')) -Encoding UTF8
}

function Assert-NetworkUnchanged {
    param([Parameter(Mandatory = $true)]$Baseline, [Parameter(Mandatory = $true)]$Observed, [Parameter(Mandatory = $true)][string]$Stage)
    $comparison = Compare-ProtectedSnapshot -Before $Baseline -After $Observed
    if (-not $comparison.Match) { throw ($Stage + ' changed protected network state: ' + (@($comparison.Differences) -join ', ')) }
    if ((Get-ProgramLockRuleCount) -ne 0) { throw ($Stage + ' created a QuietShield Program Lock rule.') }
    return $comparison
}

function Get-ComponentManifestPayloadHash {
    param([Parameter(Mandatory = $true)]$Manifest)
    $lines = @($Manifest.files | Sort-Object -Property relativePath | ForEach-Object { ([string]$_.relativePath) + '|' + ([string]$_.sha256).ToUpperInvariant() + '|' + [string][long]$_.length })
    $canonical = @([string][int]$Manifest.schemaVersion,[string]$Manifest.productMarker,[string]$Manifest.purpose,[string]$Manifest.component,[string]$Manifest.version,[string]$Manifest.runtimeIdentifier,([bool]$Manifest.selfContained).ToString(),($lines -join "`n")) -join '|'
    return Get-Utf8Sha256 -Value $canonical
}

function Test-InstalledComponentManifest {
    param([string]$ComponentRoot, [string]$ExpectedComponent, [string]$ExpectedVersion)
    $manifestPath = Join-Path $ComponentRoot 'quietshield-component-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw ('Installed component manifest is missing: ' + $ExpectedComponent) }
    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    if ([int]$manifest.schemaVersion -ne 1 -or [string]$manifest.productMarker -cne 'QuietShield' -or [string]$manifest.purpose -cne 'SelfContainedInstallerComponent' -or
        [string]$manifest.component -cne $ExpectedComponent -or [string]$manifest.version -cne $ExpectedVersion -or [string]$manifest.runtimeIdentifier -cne 'win-x64' -or -not [bool]$manifest.selfContained) {
        throw ('Installed component identity is invalid: ' + $ExpectedComponent)
    }
    foreach ($entry in @($manifest.files)) {
        $relativePath = [string]$entry.relativePath
        if ([string]::IsNullOrWhiteSpace($relativePath) -or [IO.Path]::IsPathRooted($relativePath) -or $relativePath.Contains('..')) { throw 'Installed component manifest contains an unsafe path.' }
        $installedPath = Join-Path $ComponentRoot $relativePath
        if (-not (Test-Path -LiteralPath $installedPath -PathType Leaf) -or (Get-FileSha256 -Path $installedPath) -cne ([string]$entry.sha256).ToUpperInvariant() -or (Get-Item -LiteralPath $installedPath).Length -ne [long]$entry.length) {
            throw ('Installed component file failed validation: ' + $installedPath)
        }
    }
    $actualRelativePaths = @(Get-ChildItem -LiteralPath $ComponentRoot -File -Recurse -ErrorAction Stop | Where-Object { $_.FullName -cne $manifestPath } | ForEach-Object { $_.FullName.Substring($ComponentRoot.Length + 1).Replace('\','/') } | Sort-Object)
    $expectedRelativePaths = @($manifest.files | ForEach-Object { ([string]$_.relativePath).Replace('\','/') } | Sort-Object)
    if (($actualRelativePaths -join '|') -cne ($expectedRelativePaths -join '|')) { throw ('Installed component inventory differs: ' + $ExpectedComponent) }
    if ((Get-ComponentManifestPayloadHash -Manifest $manifest) -cne ([string]$manifest.payloadSha256).ToUpperInvariant()) { throw ('Installed component payload hash is invalid: ' + $ExpectedComponent) }
    return $manifest
}

function Get-ProductionConfigurationPayloadHash {
    param([Parameter(Mandatory = $true)]$Configuration)
    $roots = @($Configuration.approvedProgramRoots | ForEach-Object { [IO.Path]::GetFullPath([string]$_).TrimEnd('\').TrimEnd('/') } | Sort-Object)
    $canonical = @([string][int]$Configuration.schemaVersion,[string]$Configuration.productMarker,[string]$Configuration.purpose,[string]$Configuration.serviceName,([Guid][string]$Configuration.installationId).ToString('D'),[string]$Configuration.authorizedUserSid,($roots -join '~'),[IO.Path]::GetFullPath([string]$Configuration.enforcementScriptPath),([string]$Configuration.enforcementScriptSha256).ToUpperInvariant(),([DateTimeOffset]$Configuration.createdAtUtc).ToUniversalTime().ToString('O')) -join '|'
    return Get-Utf8Sha256 -Value $canonical
}

function Get-ProductionOwnershipPayloadHash {
    param([Parameter(Mandatory = $true)]$Manifest)
    $canonical = @([string][int]$Manifest.schemaVersion,[string]$Manifest.productMarker,[string]$Manifest.purpose,[string]$Manifest.installerAppId,[string]$Manifest.version,[string]$Manifest.serviceName,[string]$Manifest.displayName,[IO.Path]::GetFullPath([string]$Manifest.productRoot),[IO.Path]::GetFullPath([string]$Manifest.serviceRoot),[IO.Path]::GetFullPath([string]$Manifest.executablePath),([string]$Manifest.executableSha256).ToUpperInvariant(),[IO.Path]::GetFullPath([string]$Manifest.configurationPath),([string]$Manifest.configurationSha256).ToUpperInvariant(),[string]$Manifest.binaryPathName,[string]$Manifest.authorizedUserSid,([Guid][string]$Manifest.installationId).ToString('D'),([DateTimeOffset]$Manifest.installedAtUtc).ToUniversalTime().ToString('O')) -join '|'
    return Get-Utf8Sha256 -Value $canonical
}

function Test-InstalledProduct {
    param([Parameter(Mandatory = $true)][string]$Version, [Parameter(Mandatory = $true)]$PackageManifest, [Parameter(Mandatory = $true)][string]$StageLabel)
    $appRoot = Join-Path $script:ProductRoot ('App\' + $Version)
    $serviceRoot = Join-Path $script:ProductRoot ('Service\' + $Version)
    $installerRoot = Join-Path $script:ProductRoot 'Installer'
    $appManifest = Test-InstalledComponentManifest -ComponentRoot $appRoot -ExpectedComponent 'QuietShield.App' -ExpectedVersion $Version
    $serviceManifest = Test-InstalledComponentManifest -ComponentRoot $serviceRoot -ExpectedComponent 'QuietShield.Service' -ExpectedVersion $Version
    foreach ($requiredPath in @((Join-Path $appRoot 'QuietShield.App.exe'),(Join-Path $appRoot 'coreclr.dll'),(Join-Path $appRoot 'hostfxr.dll'),(Join-Path $appRoot 'PresentationFramework.dll'),(Join-Path $serviceRoot 'QuietShield.Service.exe'),(Join-Path $serviceRoot 'coreclr.dll'),(Join-Path $serviceRoot 'hostfxr.dll'))) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) { throw ($StageLabel + ' is missing a self-contained runtime file: ' + $requiredPath) }
    }
    foreach ($entry in @($PackageManifest.inventory | Where-Object { [string]$_.relativePath -like 'payload/installer/*' })) {
        $relativePath = ([string]$entry.relativePath).Substring('payload/installer/'.Length).Replace('/','\')
        $helperPath = Join-Path $installerRoot $relativePath
        if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf) -or (Get-FileSha256 -Path $helperPath) -cne ([string]$entry.sha256).ToUpperInvariant()) { throw ($StageLabel + ' installer helper validation failed: ' + $relativePath) }
    }
    $registrations = @(Get-ExactUninstallRegistrations)
    $allRegistrations = @(Get-AllQuietShieldUninstallRegistrations)
    if ($registrations.Count -ne 1 -or $allRegistrations.Count -ne 1) { throw ($StageLabel + ' has an ambiguous or duplicate uninstall registration.') }
    if ([string]$registrations[0].DisplayName -cne 'QuietShield Windows' -or [string]$registrations[0].DisplayVersion -cne $Version) { throw ($StageLabel + ' uninstall product identity is incorrect.') }
    $services = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='QuietShieldService'" -ErrorAction Stop)
    if ($services.Count -ne 1) { throw ($StageLabel + ' requires exactly one QuietShieldService registration.') }
    $service = $services[0]
    if ([string]$service.DisplayName -cne 'QuietShield Protection Service' -or [string]$service.State -cne 'Running' -or [string]$service.StartMode -cne 'Auto' -or [string]$service.StartName -cne 'LocalSystem') { throw ($StageLabel + ' service registration/start state is invalid.') }
    $delayedStart = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\QuietShieldService' -Name DelayedAutoStart -ErrorAction Stop
    if ([int]$delayedStart.DelayedAutoStart -ne 1) { throw ($StageLabel + ' service is not Automatic Delayed Start.') }
    $ownershipPath = Join-Path $script:StateRoot 'service-ownership.json'
    $configurationPath = Join-Path $script:StateRoot 'production-config.json'
    if (-not (Test-Path -LiteralPath $ownershipPath -PathType Leaf) -or -not (Test-Path -LiteralPath $configurationPath -PathType Leaf)) { throw ($StageLabel + ' exact production ownership/configuration is missing.') }
    $ownership = Get-Content -Raw -LiteralPath $ownershipPath | ConvertFrom-Json
    $configuration = Get-Content -Raw -LiteralPath $configurationPath | ConvertFrom-Json
    if ([int]$ownership.schemaVersion -ne 1 -or [string]$ownership.productMarker -cne 'QuietShield' -or [string]$ownership.purpose -cne 'QuietShieldProductionServiceOwnership' -or [string]$ownership.installerAppId -cne $script:InstallerAppId -or [string]$ownership.version -cne $Version -or [string]$ownership.serviceName -cne 'QuietShieldService') { throw ($StageLabel + ' ownership identity is invalid.') }
    if ((Get-ProductionOwnershipPayloadHash -Manifest $ownership) -cne ([string]$ownership.payloadSha256).ToUpperInvariant()) { throw ($StageLabel + ' ownership payload hash is invalid.') }
    if ([string]$service.PathName -cne [string]$ownership.binaryPathName) { throw ($StageLabel + ' service command line differs from exact ownership.') }
    if ((Get-FileSha256 -Path ([string]$ownership.executablePath)) -cne ([string]$ownership.executableSha256).ToUpperInvariant() -or (Get-FileSha256 -Path $configurationPath) -cne ([string]$ownership.configurationSha256).ToUpperInvariant()) { throw ($StageLabel + ' owned production file hash is invalid.') }
    if ([int]$configuration.schemaVersion -ne 1 -or [string]$configuration.productMarker -cne 'QuietShield' -or [string]$configuration.purpose -cne 'QuietShieldProductionService' -or [string]$configuration.serviceName -cne 'QuietShieldService' -or [Guid][string]$configuration.installationId -ne [Guid][string]$ownership.installationId) { throw ($StageLabel + ' production configuration identity is invalid.') }
    if ((Get-ProductionConfigurationPayloadHash -Configuration $configuration) -cne ([string]$configuration.payloadSha256).ToUpperInvariant()) { throw ($StageLabel + ' production configuration payload hash is invalid.') }
    $recovery = Invoke-LoggedNativeProcess -FilePath (Join-Path $env:SystemRoot 'System32\sc.exe') -Arguments @('qfailure','QuietShieldService') -LogLabel ($StageLabel + '-service-recovery') -TimeoutSeconds 30
    $restartActions = @([regex]::Matches([string]$recovery.StdOut, '(?im)RESTART\s*--\s*Delay\s*=\s*60000')).Count
    if ([string]$recovery.StdOut -notmatch '86400' -or $restartActions -ne 3) { throw ($StageLabel + ' service recovery configuration is not three 60-second restarts with a one-day reset.') }
    $failureFlag = Invoke-LoggedNativeProcess -FilePath (Join-Path $env:SystemRoot 'System32\sc.exe') -Arguments @('qfailureflag','QuietShieldService') -LogLabel ($StageLabel + '-service-failure-flag') -TimeoutSeconds 30
    if ([string]$failureFlag.StdOut -notmatch '(?i)TRUE') { throw ($StageLabel + ' non-crash failure recovery is not enabled.') }
    if ((Get-ProgramLockRuleCount) -ne 0) { throw ($StageLabel + ' unexpectedly created a Program Lock rule.') }
    return [pscustomobject][ordered]@{ Version = $Version; AppRoot = $appRoot; ServiceRoot = $serviceRoot; AppExecutable = Join-Path $appRoot 'QuietShield.App.exe'; ServiceExecutable = Join-Path $serviceRoot 'QuietShield.Service.exe'; InstallationId = [string]$ownership.installationId; AppFiles = @($appManifest.files).Count; ServiceFiles = @($serviceManifest.files).Count }
}

function Test-ServiceAndDesktopSmoke {
    param([Parameter(Mandatory = $true)]$Installed, [Parameter(Mandatory = $true)][string]$StageLabel)
    $ipcPath = Join-Path $script:AttemptRoot ($StageLabel + '-service-ipc.json')
    [void](Invoke-LoggedNativeProcess -FilePath ([string]$Installed.ServiceExecutable) -Arguments @('--ipc-smoke','--pipe-name','QuietShield.Service.v1','--output',$ipcPath) -LogLabel ($StageLabel + '-service-ipc') -TimeoutSeconds 60)
    $ipcResult = Get-Content -Raw -LiteralPath $ipcPath | ConvertFrom-Json
    if ([string]$ipcResult.status -cne 'Passed' -or -not [bool]$ipcResult.serviceStatus.persistentEnforcementAvailable) { throw ($StageLabel + ' service IPC smoke did not pass with persistent enforcement available.') }
    $guiPath = Join-Path $script:AttemptRoot ($StageLabel + '-gui-validation.json')
    $planPath = Join-Path $script:AttemptRoot ($StageLabel + '-plan.json')
    $diagnosticPath = Join-Path $script:AttemptRoot ($StageLabel + '-desktop-diagnostic.json')
    [void](Invoke-LoggedNativeProcess -FilePath ([string]$Installed.AppExecutable) -Arguments @('--phase11-smoke','--service-pipe-name','QuietShield.Service.v1','--gui-validation-output',$guiPath,'--plan-export-output',$planPath,'--diagnostic-output',$diagnosticPath) -LogLabel ($StageLabel + '-desktop-smoke') -TimeoutSeconds 120)
    $guiResult = Get-Content -Raw -LiteralPath $guiPath | ConvertFrom-Json
    if ([string]$guiResult.Status -cne 'Passed' -or -not [bool]$guiResult.ServiceStatusRefreshSucceeded) { throw ($StageLabel + ' installed desktop launch/IPC smoke did not pass.') }
    return [pscustomobject][ordered]@{ ServiceIpc = 'Passed'; DesktopLaunch = 'Passed'; DesktopServiceStatus = 'Passed' }
}

function Invoke-InstallerPackage {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Label)
    $logPath = Join-Path $script:AttemptRoot ($Label + '-inno.log')
    $script:ForwardChangeStarted = $true
    [void](Invoke-LoggedNativeProcess -FilePath $Path -Arguments @('/SILENT','/NORESTART','/SP-',('/LOG=' + $logPath)) -LogLabel $Label -TimeoutSeconds 1200)
}

function Get-UninstallerPath {
    $registrations = @(Get-ExactUninstallRegistrations)
    if ($registrations.Count -ne 1) { throw 'The exact supported QuietShield uninstaller registration is missing or ambiguous.' }
    $commandText = [string]$registrations[0].QuietUninstallString
    if ([string]::IsNullOrWhiteSpace($commandText)) { $commandText = [string]$registrations[0].UninstallString }
    $match = [regex]::Match($commandText, '^\s*"([^"]+\.exe)"')
    if (-not $match.Success) { $match = [regex]::Match($commandText, '^\s*(.+?\.exe)(?:\s|$)') }
    if (-not $match.Success) { throw 'The exact supported uninstaller command is malformed.' }
    $uninstallerPath = [IO.Path]::GetFullPath($match.Groups[1].Value).Trim()
    $allowedPrefix = $script:ProductRoot + '\'
    if (-not $uninstallerPath.StartsWith($allowedPrefix, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($uninstallerPath) -notmatch '\Aunins\d{3}\.exe\z' -or -not (Test-Path -LiteralPath $uninstallerPath -PathType Leaf)) { throw 'The registered uninstaller is outside the exact QuietShield product root or unavailable.' }
    return $uninstallerPath
}

function Invoke-ExactSupportedUninstall {
    param([Parameter(Mandatory = $true)][string]$Label)
    $uninstallerPath = Get-UninstallerPath
    $logPath = Join-Path $script:AttemptRoot ($Label + '-inno-uninstall.log')
    [void](Invoke-LoggedNativeProcess -FilePath $uninstallerPath -Arguments @('/SILENT','/NORESTART',('/LOG=' + $logPath)) -LogLabel $Label -TimeoutSeconds 1200)
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        if (@(Get-CimInstance -ClassName Win32_Service -Filter "Name='QuietShieldService'" -ErrorAction SilentlyContinue).Count -eq 0 -and @(Get-ExactUninstallRegistrations).Count -eq 0) { break }
        Start-Sleep -Milliseconds 500
    }
    if (@(Get-CimInstance -ClassName Win32_Service -Filter "Name='QuietShieldService'" -ErrorAction SilentlyContinue).Count -ne 0 -or @(Get-ExactUninstallRegistrations).Count -ne 0) { throw 'The exact supported uninstaller left service or registration residue.' }
}

function Get-GenuineOlderInstaller {
    $installerRoot = Join-Path $script:RepositoryRoot 'artifacts\installer'
    $targetCore = [version]'0.12.0'
    $candidates = @()
    if (Test-Path -LiteralPath $installerRoot -PathType Container) {
        foreach ($candidate in @(Get-ChildItem -LiteralPath $installerRoot -Filter 'QuietShield-Windows-x64-*.exe' -File -Recurse -ErrorAction Stop)) {
            if ($candidate.FullName.Equals($script:InstallerPath, [StringComparison]::OrdinalIgnoreCase)) { continue }
            if ($candidate.Name -notmatch '\AQuietShield-Windows-x64-(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\.exe\z') { continue }
            $candidateVersion = $Matches[1]
            if ($candidateVersion -notmatch '\A(\d+\.\d+\.\d+)') { continue }
            if ([version]$Matches[1] -ge $targetCore) { continue }
            $candidateRoot = $candidate.Directory.Parent.FullName
            $candidateManifestPath = Join-Path $candidateRoot 'phase12-package-manifest.json'
            if (-not (Test-Path -LiteralPath $candidateManifestPath -PathType Leaf)) { continue }
            $candidateManifest = Get-Content -Raw -LiteralPath $candidateManifestPath | ConvertFrom-Json
            if ([int]$candidateManifest.schemaVersion -ne 1 -or [string]$candidateManifest.productMarker -cne 'QuietShield' -or [string]$candidateManifest.purpose -cne 'QuietShieldBetaInstallerPackage' -or [string]$candidateManifest.version -cne $candidateVersion -or [string]$candidateManifest.architecture -cne 'x64' -or -not [bool]$candidateManifest.selfContained) { continue }
            if ((Get-FileSha256 -Path $candidate.FullName) -cne ([string]$candidateManifest.installerSha256).ToUpperInvariant()) { continue }
            $candidates += [pscustomobject][ordered]@{ Path = $candidate.FullName; Version = $candidateVersion; CoreVersion = [version]$Matches[1]; Manifest = $candidateManifest }
        }
    }
    if ($candidates.Count -eq 0) { return $null }
    return @($candidates | Sort-Object -Property CoreVersion -Descending)[0]
}

function Test-Preflight {
    if ($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'This rehearsal requires Windows PowerShell 5.1.' }
    if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) { throw 'This rehearsal requires 64-bit Windows PowerShell on Windows x64.' }
    if (-not (Test-IsAdministrator)) { throw 'Administrator approval is absent. Close this console, right-click the BAT launcher, and choose Run as administrator.' }
    if (-not (Test-Path -LiteralPath $script:InstallerPath -PathType Leaf)) { throw 'The exact Phase 12 installer is missing.' }
    $installerHash = Get-FileSha256 -Path $script:InstallerPath
    if ($installerHash -cne $script:ExpectedInstallerHash) { throw ('Installer SHA-256 mismatch. Actual: ' + $installerHash) }
    $signature = Get-AuthenticodeSignature -LiteralPath $script:InstallerPath
    if ([string]$signature.Status -cne 'NotSigned') { throw ('The selected installer signing state changed. Expected NotSigned; actual: ' + [string]$signature.Status) }
    if (-not (Test-Path -LiteralPath $script:PackageManifestPath -PathType Leaf) -or -not (Test-Path -LiteralPath $script:PackageValidationPath -PathType Leaf)) { throw 'Phase 12 package evidence is missing.' }
    $manifest = Get-Content -Raw -LiteralPath $script:PackageManifestPath | ConvertFrom-Json
    $validation = Get-Content -Raw -LiteralPath $script:PackageValidationPath | ConvertFrom-Json
    if ([int]$manifest.schemaVersion -ne 1 -or [string]$manifest.productMarker -cne 'QuietShield' -or [string]$manifest.purpose -cne 'QuietShieldBetaInstallerPackage' -or [string]$manifest.version -cne $script:ExpectedVersion -or [string]$manifest.architecture -cne 'x64' -or -not [bool]$manifest.selfContained -or [string]$manifest.sourceCommit -cne $script:ExpectedPackageSource -or [string]$manifest.installerSha256 -cne $script:ExpectedInstallerHash) { throw 'The package manifest does not identify the exact approved self-contained beta.' }
    if ([string]$validation.status -cne 'Passed' -or [string]$validation.version -cne $script:ExpectedVersion -or [string]$validation.installerSha256 -cne $script:ExpectedInstallerHash -or [string]$validation.signingStatus -cne 'NotSigned' -or [string]$validation.realInstallTest -cne 'NotYetAttempted') { throw 'The static Phase 12 validation evidence is inconsistent.' }
    $gitPath = (Get-Command git.exe -ErrorAction Stop).Source
    $branch = (Invoke-ReadOnlyNativeProcess -FilePath $gitPath -Arguments @('-C',$script:RepositoryRoot,'branch','--show-current')).StdOut.Trim()
    $head = (Invoke-ReadOnlyNativeProcess -FilePath $gitPath -Arguments @('-C',$script:RepositoryRoot,'rev-parse','HEAD')).StdOut.Trim()
    $remoteFeature = (Invoke-ReadOnlyNativeProcess -FilePath $gitPath -Arguments @('-C',$script:RepositoryRoot,'rev-parse',('origin/' + $script:ExpectedBranch))).StdOut.Trim()
    $main = (Invoke-ReadOnlyNativeProcess -FilePath $gitPath -Arguments @('-C',$script:RepositoryRoot,'rev-parse','main')).StdOut.Trim()
    $remoteMain = (Invoke-ReadOnlyNativeProcess -FilePath $gitPath -Arguments @('-C',$script:RepositoryRoot,'rev-parse','origin/main')).StdOut.Trim()
    if ($branch -cne $script:ExpectedBranch -or $head -cne $script:ExpectedHead -or $remoteFeature -cne $script:ExpectedHead -or $main -cne $script:ExpectedMain -or $remoteMain -cne $script:ExpectedMain) { throw 'The Phase 12 source branch, HEAD, origin feature, or main identity changed.' }
    $statusText = (Invoke-ReadOnlyNativeProcess -FilePath $gitPath -Arguments @('-C',$script:RepositoryRoot,'status','--porcelain','--untracked-files=all')).StdOut
    $statusRows = @($statusText -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $allowedRows = @('?? RUN-PHASE12-INSTALLER-REHEARSAL-AS-ADMIN.bat','?? Run-Phase12-Installer-Rehearsal.ps1')
    if ($statusRows.Count -ne 2 -or @($statusRows | Where-Object { $_ -notin $allowedRows }).Count -ne 0) { throw ('The working tree contains changes outside the two approved one-time rehearsal files: ' + ($statusRows -join ' | ')) }
    $diffCheck = (Invoke-ReadOnlyNativeProcess -FilePath $gitPath -Arguments @('-C',$script:RepositoryRoot,'diff','--check')).StdOut
    if (-not [string]::IsNullOrWhiteSpace($diffCheck)) { throw ('git diff --check failed: ' + $diffCheck.Trim()) }
    if (@(Get-CimInstance -ClassName Win32_Service -Filter "Name='QuietShieldService'" -ErrorAction SilentlyContinue).Count -ne 0) { throw 'QuietShieldService must be absent before the rehearsal.' }
    if (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\QuietShieldService') { throw 'An orphaned QuietShieldService registry key exists.' }
    if ((Get-ProgramLockRuleCount) -ne 0) { throw 'QuietShield Program Lock rules must be absent before the rehearsal.' }
    if (@(Get-AllQuietShieldUninstallRegistrations).Count -ne 0) { throw 'A conflicting QuietShield uninstall registration exists.' }
    if (Test-Path -LiteralPath $script:ProductRoot -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $script:ProductRoot -Force -ErrorAction Stop).Count -ne 0) { throw 'The production QuietShield Program Files location is not clean.' }
    }
    foreach ($ownershipPath in @((Join-Path $script:StateRoot 'service-ownership.json'),(Join-Path $script:StateRoot 'production-config.json'))) {
        if (Test-Path -LiteralPath $ownershipPath -PathType Leaf) { throw ('Conflicting production state exists: ' + $ownershipPath) }
    }
    if (@(Get-DirectoryInventory -Path $script:StateRoot).Count -ne 0) { throw 'The production QuietShield ProgramData state location is not clean.' }
    if (@(Get-Process -Name 'QuietShield.App' -ErrorAction SilentlyContinue).Count -ne 0) { throw 'QuietShield.App is already running and must be closed before the rehearsal.' }
    return [pscustomobject][ordered]@{ Manifest = $manifest; InstallerHash = $installerHash; SignatureStatus = [string]$signature.Status; Branch = $branch; Head = $head; OlderInstaller = Get-GenuineOlderInstaller; Snapshot = Get-ProtectedSnapshot; StateInventory = @(Get-DirectoryInventory -Path $script:StateRoot); UserDataInventory = @(Get-DirectoryInventory -Path $script:UserDataRoot) }
}

function Get-ResidueSummary {
    $serviceCount = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='QuietShieldService'" -ErrorAction SilentlyContinue).Count
    $ruleCount = Get-ProgramLockRuleCount
    $registrationCount = @(Get-AllQuietShieldUninstallRegistrations).Count
    $installFiles = @(Get-DirectoryInventory -Path $script:ProductRoot)
    $stateFiles = @(Get-DirectoryInventory -Path $script:StateRoot)
    return [pscustomobject][ordered]@{ ServiceCount = $serviceCount; ProgramLockRuleCount = $ruleCount; RegistrationCount = $registrationCount; InstallFiles = $installFiles; StateFiles = $stateFiles }
}

$exitCode = 1
try {
    Write-Host 'QuietShield Phase 12 controlled installer rehearsal'
    Write-Host 'No Windows security feature will be disabled or bypassed.'
    Write-Host 'Running read-only preflight checks...'
    $preflight = Test-Preflight
    Write-Host ('Preflight passed. Installer SHA-256: ' + [string]$preflight.InstallerHash)
    Write-Host ('Signing status: ' + [string]$preflight.SignatureStatus + '. Windows security must remain enabled.')
    $approval = Read-Host ('Type exactly: ' + $script:ExpectedApproval)
    if ($approval -cne $script:ExpectedApproval) { throw 'The exact approval phrase was not supplied. No rehearsal changes were made.' }

    New-Item -ItemType Directory -Path $script:WorkRoot -Force | Out-Null
    $attemptId = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N')
    $attemptsRoot = Join-Path $script:WorkRoot 'attempts'
    New-Item -ItemType Directory -Path $attemptsRoot -Force | Out-Null
    $script:AttemptRoot = Join-Path $attemptsRoot $attemptId
    New-Item -ItemType Directory -Path $script:AttemptRoot -Force | Out-Null
    $lockPath = Join-Path $script:WorkRoot 'phase12-installer-rehearsal.lock'
    $script:LockStream = New-Object IO.FileStream($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $lockBytes = (New-Object Text.UTF8Encoding($false)).GetBytes(('pid=' + [string]$PID + '; started=' + [DateTimeOffset]::UtcNow.ToString('O')))
    $script:LockStream.SetLength(0)
    $script:LockStream.Write($lockBytes,0,$lockBytes.Length)
    $script:LockStream.Flush()
    Start-Transcript -LiteralPath (Join-Path $script:AttemptRoot 'rehearsal-transcript.log') -Force | Out-Null
    $script:TranscriptStarted = $true
    $script:Result.Status = 'Running'
    Write-Checkpoint -Stage 'ApprovalAccepted'

    $baseline = Get-ProtectedSnapshot
    $preflightComparison = Compare-ProtectedSnapshot -Before $preflight.Snapshot -After $baseline -IncludeServiceAndRestart
    if (-not $preflightComparison.Match) { throw ('Protected state changed while approval was pending: ' + (@($preflightComparison.Differences) -join ', ')) }
    if (@(Get-CimInstance -ClassName Win32_Service -Filter "Name='QuietShieldService'" -ErrorAction SilentlyContinue).Count -ne 0 -or
        (Get-ProgramLockRuleCount) -ne 0 -or @(Get-AllQuietShieldUninstallRegistrations).Count -ne 0) {
        throw 'The clean service, Firewall, or uninstall-registration preflight changed while approval was pending.'
    }
    Save-Snapshot -Snapshot $baseline -Name 'baseline-protected-state'
    [pscustomobject][ordered]@{ branch = $preflight.Branch; head = $preflight.Head; installerPath = $script:InstallerPath; installerSha256 = $preflight.InstallerHash; signatureStatus = $preflight.SignatureStatus; olderInstaller = $preflight.OlderInstaller; stateInventory = $preflight.StateInventory; userDataInventory = $preflight.UserDataInventory } | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $script:AttemptRoot 'preflight.json') -Encoding UTF8
    Write-Checkpoint -Stage 'BaselineCaptured'

    Invoke-InstallerPackage -Path $script:InstallerPath -Label 'fresh-install'
    $freshInstalled = Test-InstalledProduct -Version $script:ExpectedVersion -PackageManifest $preflight.Manifest -StageLabel 'fresh-install'
    $freshSmoke = Test-ServiceAndDesktopSmoke -Installed $freshInstalled -StageLabel 'fresh-install'
    $afterFresh = Get-ProtectedSnapshot
    Save-Snapshot -Snapshot $afterFresh -Name 'after-fresh-install-protected-state'
    [void](Assert-NetworkUnchanged -Baseline $baseline -Observed $afterFresh -Stage 'Fresh install')
    if ([string]$baseline.PendingRenameHash -cne [string]$afterFresh.PendingRenameHash) { $script:Result.RestartRequired = 'YES'; throw 'Fresh install created a pending restart requirement; forward rehearsal steps stopped.' }
    $script:Result.FreshInstall = 'PASSED for ' + $script:ExpectedVersion
    $script:Result.ServiceRegistrationStart = 'PASSED; exactly one running Automatic Delayed Start LocalSystem service with validated recovery'
    $script:Result.IpcAppStartup = 'PASSED; service IPC and installed Phase 11 desktop smoke passed'
    $script:Result.ProgramLockRulesAfterInstall = '0'
    $script:Result.DnsComparison = 'PASSED after fresh install'
    $script:Result.SystemChanges = 'Exact QuietShield product installed for controlled validation'
    Write-Checkpoint -Stage 'FreshInstallValidated'

    if ($null -eq $preflight.OlderInstaller) {
        $freshInstallationId = [string]$freshInstalled.InstallationId
        Invoke-InstallerPackage -Path $script:InstallerPath -Label 'same-version-reinstall'
        $reinstalled = Test-InstalledProduct -Version $script:ExpectedVersion -PackageManifest $preflight.Manifest -StageLabel 'same-version-reinstall'
        if ([string]$reinstalled.InstallationId -cne $freshInstallationId) { throw 'Same-version reinstall replaced the deterministic production installation identity.' }
        $afterReinstall = Get-ProtectedSnapshot
        Save-Snapshot -Snapshot $afterReinstall -Name 'after-reinstall-protected-state'
        [void](Assert-NetworkUnchanged -Baseline $baseline -Observed $afterReinstall -Stage 'Same-version reinstall')
        if ([string]$baseline.PendingRenameHash -cne [string]$afterReinstall.PendingRenameHash) { $script:Result.RestartRequired = 'YES'; throw 'Same-version reinstall created a pending restart requirement; forward rehearsal steps stopped.' }
        $script:Result.ReinstallUpgradeResult = 'PASSED same-version reinstall/repair; no genuine older compatible artifact existed'
        $script:Result.UpgradeActuallyProven = 'NO'
    }
    else {
        Invoke-ExactSupportedUninstall -Label 'prepare-genuine-upgrade'
        $betweenVersions = Get-ProtectedSnapshot
        [void](Assert-NetworkUnchanged -Baseline $baseline -Observed $betweenVersions -Stage 'Exact preparation uninstall')
        Invoke-InstallerPackage -Path ([string]$preflight.OlderInstaller.Path) -Label 'older-version-install'
        $olderInstalled = Test-InstalledProduct -Version ([string]$preflight.OlderInstaller.Version) -PackageManifest $preflight.OlderInstaller.Manifest -StageLabel 'older-version-install'
        Invoke-InstallerPackage -Path $script:InstallerPath -Label 'genuine-upgrade'
        $upgraded = Test-InstalledProduct -Version $script:ExpectedVersion -PackageManifest $preflight.Manifest -StageLabel 'genuine-upgrade'
        if ([string]$upgraded.InstallationId -cne [string]$olderInstalled.InstallationId) { throw 'Genuine upgrade replaced the deterministic production installation identity.' }
        $afterUpgrade = Get-ProtectedSnapshot
        Save-Snapshot -Snapshot $afterUpgrade -Name 'after-genuine-upgrade-protected-state'
        [void](Assert-NetworkUnchanged -Baseline $baseline -Observed $afterUpgrade -Stage 'Genuine upgrade')
        if ([string]$baseline.PendingRenameHash -cne [string]$afterUpgrade.PendingRenameHash) { $script:Result.RestartRequired = 'YES'; throw 'Genuine upgrade created a pending restart requirement; forward rehearsal steps stopped.' }
        $script:Result.ReinstallUpgradeResult = 'PASSED genuine upgrade from ' + [string]$preflight.OlderInstaller.Version + ' to ' + $script:ExpectedVersion
        $script:Result.UpgradeActuallyProven = 'YES'
    }
    $script:Result.DnsComparison = 'PASSED after install and reinstall/upgrade'
    Write-Checkpoint -Stage 'ReinstallOrUpgradeValidated'

    Invoke-ExactSupportedUninstall -Label 'final-uninstall'
    $afterUninstall = Get-ProtectedSnapshot
    Save-Snapshot -Snapshot $afterUninstall -Name 'after-uninstall-protected-state'
    $finalComparison = Compare-ProtectedSnapshot -Before $baseline -After $afterUninstall -IncludeServiceAndRestart
    $residue = Get-ResidueSummary
    $finalUserData = @(Get-DirectoryInventory -Path $script:UserDataRoot)
    [pscustomobject][ordered]@{ stateFiles = $residue.StateFiles; userDataBefore = $preflight.UserDataInventory; userDataAfter = $finalUserData } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $script:AttemptRoot 'intentional-state-and-user-data-residue.json') -Encoding UTF8
    $script:Result.ServiceResidue = [string]$residue.ServiceCount
    $script:Result.InstallRootResidue = [string]$residue.InstallFiles.Count + ' file(s)'
    $script:Result.UninstallRegistrationResidue = [string]$residue.RegistrationCount
    $script:Result.ProgramLockRuleResidue = [string]$residue.ProgramLockRuleCount
    $script:Result.ProtectedStateComparison = 'PASSED'
    $script:Result.DnsComparison = 'PASSED; exact original DNS snapshot restored'
    if ([string]$baseline.PendingRenameHash -cne [string]$afterUninstall.PendingRenameHash) { $script:Result.RestartRequired = 'YES' }
    if (-not $finalComparison.Match -or $residue.ServiceCount -ne 0 -or $residue.ProgramLockRuleCount -ne 0 -or $residue.RegistrationCount -ne 0 -or $residue.InstallFiles.Count -ne 0) {
        $script:Result.ProtectedStateComparison = 'FAILED: ' + (@($finalComparison.Differences) -join ', ')
        throw 'Final uninstall residue or protected-state mismatch remains; no broad cleanup was attempted.'
    }
    $script:Result.UninstallResult = 'PASSED through the exact registered Inno uninstaller; ProgramData evidence was preserved'
    $script:Result.Status = 'PASSED'
    $script:Result.SystemChanges = 'Temporary exact install/reinstall-or-upgrade/uninstall completed; final protected Windows state restored; evidence retained under D:\QuietShield-Phase12-Work'
    $script:Result.CleanupRequired = 'NO'
    Write-Checkpoint -Stage 'Completed'
    $exitCode = 0
}
catch {
    $script:Result.Status = 'FAILED'
    $script:Result.Failure = $_.Exception.Message
    $script:Result.SystemChanges = 'Rehearsal stopped after the exact failure; evidence preserved'
    if ($null -ne $script:TimedOutProcessId) {
        $script:Result.CleanupRequired = 'YES; timed-out process PID ' + [string]$script:TimedOutProcessId + ' was not terminated'
    }
    elseif ($script:ForwardChangeStarted -and -not [string]::IsNullOrWhiteSpace($script:AttemptRoot)) {
        try {
            if (@(Get-ExactUninstallRegistrations).Count -eq 1) {
                Invoke-ExactSupportedUninstall -Label 'failure-supported-rollback'
                $script:Result.UninstallResult = 'Exact supported rollback/uninstall completed after failure'
            }
        }
        catch {
            $script:Result.UninstallResult = 'Exact supported rollback/uninstall failed: ' + $_.Exception.Message
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($script:AttemptRoot)) {
        try {
            $failureSnapshot = Get-ProtectedSnapshot
            Save-Snapshot -Snapshot $failureSnapshot -Name 'failure-final-protected-state'
            $failureResidue = Get-ResidueSummary
            $script:Result.ServiceResidue = [string]$failureResidue.ServiceCount
            $script:Result.InstallRootResidue = [string]$failureResidue.InstallFiles.Count + ' file(s)'
            $script:Result.UninstallRegistrationResidue = [string]$failureResidue.RegistrationCount
            $script:Result.ProgramLockRuleResidue = [string]$failureResidue.ProgramLockRuleCount
            if ($failureResidue.ServiceCount -ne 0 -or $failureResidue.InstallFiles.Count -ne 0 -or $failureResidue.RegistrationCount -ne 0 -or $failureResidue.ProgramLockRuleCount -ne 0) { $script:Result.CleanupRequired = 'YES' }
        }
        catch {
            $script:Result.CleanupRequired = 'YES; final read-only residue capture failed'
        }
        Write-Checkpoint -Stage 'Failed'
    }
    Write-Error $_.Exception.Message
}
finally {
    if ($script:TranscriptStarted) { try { Stop-Transcript | Out-Null } catch { } }
    if ($null -ne $script:LockStream) { $script:LockStream.Dispose() }
}

exit $exitCode
