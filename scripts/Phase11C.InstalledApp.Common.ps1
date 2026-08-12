Set-StrictMode -Version 2.0

function Test-Phase11CPathUnderRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    if ([string]::IsNullOrWhiteSpace($Root)) { return $false }

    $resolvedPath = [IO.Path]::GetFullPath($Path)
    $resolvedRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    return $resolvedPath.StartsWith($resolvedRoot, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-Phase11CSafeInstalledApplicationTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]
        [ValidateSet('PythonBase','GitCurl','Node')]
        [string]$ProbeAdapter
    )

    $resolved = [IO.Path]::GetFullPath($Path)

    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw 'The selected Phase 11C executable does not exist.'
    }

    $item = Get-Item -LiteralPath $resolved -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Phase 11C refuses reparse-point application targets.'
    }

    $windowsRoot = [IO.Path]::GetFullPath($env:WINDIR).TrimEnd('\') + '\'
    if ($resolved.StartsWith($windowsRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Phase 11C refuses Windows-directory executables.'
    }

    $lower = $resolved.ToLowerInvariant()
    foreach ($fragment in @(
        '\windowsapps\',
        '\.venv\',
        '\venv\',
        '\virtualenv\',
        '\artifacts\',
        '\quietshield\service\'
    )) {
        if ($lower.Contains($fragment)) {
            throw ('Phase 11C refuses executable path fragment: ' + $fragment)
        }
    }

    $fileName = [IO.Path]::GetFileName($resolved)
    if ($fileName -cin @(
        'QuietShield.Service.exe',
        'QuietShield.App.exe',
        'QuietShield.ConnectionProbe.exe'
    )) {
        throw 'QuietShield executables cannot be selected as Phase 11C installed-application targets.'
    }

    $allowedRoots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        (Join-Path $env:LOCALAPPDATA 'Programs')
    )

    $underApprovedInstallRoot = $false
    foreach ($allowedRoot in $allowedRoots) {
        if (-not [string]::IsNullOrWhiteSpace([string]$allowedRoot) -and
            (Test-Phase11CPathUnderRoot -Path $resolved -Root ([string]$allowedRoot))) {
            $underApprovedInstallRoot = $true
            break
        }
    }

    if (-not $underApprovedInstallRoot) {
        throw 'Phase 11C accepts only executables under Program Files or LocalAppData\Programs.'
    }

    if ($ProbeAdapter -eq 'PythonBase' -and $fileName -cne 'python.exe') {
        throw 'PythonBase adapter requires python.exe.'
    }
    if ($ProbeAdapter -eq 'GitCurl' -and $fileName -cne 'curl.exe') {
        throw 'GitCurl adapter requires curl.exe.'
    }
    if ($ProbeAdapter -eq 'Node' -and $fileName -cne 'node.exe') {
        throw 'Node adapter requires node.exe.'
    }

    return $resolved
}

function Invoke-Phase11CProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ExecutablePath,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [ValidateRange(1000, 30000)][int]$TimeoutMilliseconds = 12000
    )

    New-Item -ItemType Directory -Path $WorkingDirectory -Force | Out-Null

    $token = [Guid]::NewGuid().ToString('N')
    $stdoutPath = Join-Path $WorkingDirectory ($token + '.stdout.txt')
    $stderrPath = Join-Path $WorkingDirectory ($token + '.stderr.txt')
    $process = $null
    $timedOut = $false

    try {
        $process = Start-Process `
            -FilePath $ExecutablePath `
            -ArgumentList $Arguments `
            -WorkingDirectory $WorkingDirectory `
            -WindowStyle Hidden `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath `
            -PassThru

        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            $timedOut = $true
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            try { $process.WaitForExit(3000) | Out-Null } catch {}
        }

        $exitCode = 124
        if (-not $timedOut) {
            $process.Refresh()
            $exitCode = [int]$process.ExitCode
        }

        $stdout = ''
        $stderr = ''
        if (Test-Path -LiteralPath $stdoutPath) {
            $stdout = Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $stderrPath) {
            $stderr = Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue
        }

        return [pscustomobject][ordered]@{
            exitCode = $exitCode
            timedOut = $timedOut
            stdout = [string]$stdout
            stderr = [string]$stderr
        }
    }
    finally {
        if ($null -ne $process) { $process.Dispose() }
        Remove-Item -LiteralPath $stdoutPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-Phase11CNetworkProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ExecutablePath,
        [Parameter(Mandatory = $true)]
        [ValidateSet('PythonBase','GitCurl','Node')]
        [string]$ProbeAdapter,
        [Parameter(Mandatory = $true)][string]$Address,
        [ValidateRange(1,65535)][int]$Port = 443,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )

    $resolved = Assert-Phase11CSafeInstalledApplicationTarget `
        -Path $ExecutablePath `
        -ProbeAdapter $ProbeAdapter

    New-Item -ItemType Directory -Path $WorkingDirectory -Force | Out-Null

    $arguments = @()
    $probeScript = ''

    try {
        if ($ProbeAdapter -eq 'PythonBase') {
            $probeScript = Join-Path $WorkingDirectory ('phase11c-python-' + [Guid]::NewGuid().ToString('N') + '.py')
            @'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
timeout = float(sys.argv[3])
sock = socket.create_connection((host, port), timeout=timeout)
sock.close()
'@ | Set-Content -LiteralPath $probeScript -Encoding ASCII

            $arguments = @(
                ('"' + $probeScript + '"'),
                $Address,
                [string]$Port,
                '5'
            )
        }
        elseif ($ProbeAdapter -eq 'Node') {
            $probeScript = Join-Path $WorkingDirectory ('phase11c-node-' + [Guid]::NewGuid().ToString('N') + '.js')
            @'
const net = require('net');

const host = process.argv[2];
const port = Number(process.argv[3]);
const timeoutMs = Number(process.argv[4]);

const socket = net.createConnection({ host, port });
let done = false;

function finish(code) {
    if (done) return;
    done = true;
    try { socket.destroy(); } catch (_) {}
    process.exit(code);
}

socket.setTimeout(timeoutMs);
socket.on('connect', () => finish(0));
socket.on('timeout', () => finish(10));
socket.on('error', () => finish(10));
'@ | Set-Content -LiteralPath $probeScript -Encoding ASCII

            $arguments = @(
                ('"' + $probeScript + '"'),
                $Address,
                [string]$Port,
                '5000'
            )
        }
        elseif ($ProbeAdapter -eq 'GitCurl') {
            $arguments = @(
                '--silent',
                '--show-error',
                '--connect-timeout', '5',
                '--max-time', '8',
                '--resolve', ('example.com:' + [string]$Port + ':' + $Address),
                '--output', 'NUL',
                'https://example.com/'
            )
        }

        $result = Invoke-Phase11CProcess `
            -ExecutablePath $resolved `
            -Arguments $arguments `
            -WorkingDirectory $WorkingDirectory `
            -TimeoutMilliseconds 12000

        return [pscustomobject][ordered]@{
            executablePath = $resolved
            probeAdapter = $ProbeAdapter
            address = $Address
            port = $Port
            exitCode = [int]$result.exitCode
            timedOut = [bool]$result.timedOut
            succeeded = (-not [bool]$result.timedOut -and [int]$result.exitCode -eq 0)
            stderr = [string]$result.stderr
        }
    }
    finally {
        if (-not [string]::IsNullOrWhiteSpace($probeScript)) {
            Remove-Item -LiteralPath $probeScript -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-Phase11CInstalledApplicationCandidates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )

    New-Item -ItemType Directory -Path $WorkingDirectory -Force | Out-Null

    $raw = @()

    foreach ($commandName in @('python.exe','node.exe','curl.exe')) {
        foreach ($command in @(Get-Command $commandName -CommandType Application -All -ErrorAction SilentlyContinue)) {
            $adapter = ''
            if ($commandName -ceq 'python.exe') { $adapter = 'PythonBase' }
            elseif ($commandName -ceq 'node.exe') { $adapter = 'Node' }
            elseif ($commandName -ceq 'curl.exe') { $adapter = 'GitCurl' }

            $raw += [pscustomobject]@{
                path = [string]$command.Source
                adapter = $adapter
            }
        }
    }

    foreach ($programFilesRoot in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ([string]::IsNullOrWhiteSpace([string]$programFilesRoot)) { continue }

        $gitCurl = Join-Path ([string]$programFilesRoot) 'Git\mingw64\bin\curl.exe'
        if (Test-Path -LiteralPath $gitCurl -PathType Leaf) {
            $raw += [pscustomobject]@{
                path = $gitCurl
                adapter = 'GitCurl'
            }
        }
    }

    $deduped = @{}
    foreach ($candidate in $raw) {
        if ([string]::IsNullOrWhiteSpace([string]$candidate.path)) { continue }

        try {
            $safePath = Assert-Phase11CSafeInstalledApplicationTarget `
                -Path ([string]$candidate.path) `
                -ProbeAdapter ([string]$candidate.adapter)

            $key = $safePath.ToUpperInvariant()
            if (-not $deduped.ContainsKey($key)) {
                $deduped[$key] = [pscustomobject]@{
                    path = $safePath
                    adapter = [string]$candidate.adapter
                }
            }
        }
        catch {
            continue
        }
    }

    $addresses = @(
        [Net.Dns]::GetHostAddresses('example.com') |
            Where-Object { $_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork } |
            Sort-Object -Property IPAddressToString -Unique
    )

    if ($addresses.Count -eq 0) {
        throw 'Phase 11C could not resolve an IPv4 endpoint for the preflight network probe.'
    }

    $results = @()
    foreach ($candidate in @($deduped.Values | Sort-Object -Property adapter, path)) {
        $item = Get-Item -LiteralPath ([string]$candidate.path)
        $versionInfo = $item.VersionInfo
        $selectedAddress = $null
        $probePassed = $false
        $probeError = ''

        foreach ($address in $addresses) {
            $probe = Invoke-Phase11CNetworkProbe `
                -ExecutablePath ([string]$candidate.path) `
                -ProbeAdapter ([string]$candidate.adapter) `
                -Address $address.ToString() `
                -Port 443 `
                -WorkingDirectory $WorkingDirectory

            if ([bool]$probe.succeeded) {
                $selectedAddress = $address.ToString()
                $probePassed = $true
                break
            }

            $probeError = [string]$probe.stderr
        }

        $displayName = [string]$versionInfo.ProductName
        if ([string]::IsNullOrWhiteSpace($displayName)) {
            $displayName = [IO.Path]::GetFileNameWithoutExtension([string]$candidate.path)
        }

        $results += [pscustomobject][ordered]@{
            displayName = $displayName
            executablePath = [string]$candidate.path
            probeAdapter = [string]$candidate.adapter
            version = [string]$versionInfo.ProductVersion
            company = [string]$versionInfo.CompanyName
            sha256 = Get-QuietShieldFileSha256 -Path ([string]$candidate.path)
            stableIdentity = Get-QuietShieldApprovedProgramIdentity -Path ([string]$candidate.path)
            networkProbePassed = $probePassed
            selectedProbeAddress = [string]$selectedAddress
            probePort = 443
            probeError = $probeError
        }
    }

    return @($results)
}

function Get-Phase11CRunningTargetProcesses {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ExecutablePath)

    $resolved = [IO.Path]::GetFullPath($ExecutablePath)
    $matches = @()

    foreach ($process in @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue)) {
        $path = [string]$process.ExecutablePath
        if ([string]::IsNullOrWhiteSpace($path)) { continue }

        try {
            if ([string]::Equals([IO.Path]::GetFullPath($path), $resolved, [StringComparison]::OrdinalIgnoreCase)) {
                $matches += [pscustomobject]@{
                    processId = [int]$process.ProcessId
                    name = [string]$process.Name
                    executablePath = $path
                }
            }
        }
        catch {}
    }

    return @($matches)
}
