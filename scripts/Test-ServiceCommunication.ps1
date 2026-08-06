[CmdletBinding()]
param(
    [string]$RepositoryRoot = '',
    [string]$OutputDirectory = '',
    [int]$HostDurationSeconds = 8
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')
Assert-QuietShieldPowerShell51
Assert-QuietShieldNonElevated

if ($HostDurationSeconds -lt 3 -or $HostDurationSeconds -gt 60) { throw 'HostDurationSeconds must be between 3 and 60.' }
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) { $RepositoryRoot = Get-QuietShieldRepositoryRoot }
$root = [IO.Path]::GetFullPath($RepositoryRoot)
$service = Join-Path $root 'artifacts\bin\QuietShield.Service\Debug\net10.0-windows\QuietShield.Service.exe'
if (-not (Test-Path -LiteralPath $service -PathType Leaf)) { throw ('QuietShield.Service executable was not found: ' + $service) }
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path $root 'artifacts\phase10a\ipc-smoke' }
$output = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $output -Force | Out-Null
$pipeName = 'QuietShield.Service.Validation.' + [Guid]::NewGuid().ToString('N')
$stateRoot = Join-Path $output 'state'
$hostStdout = Join-Path $output 'service.stdout.log'
$hostStderr = Join-Path $output 'service.stderr.log'
$clientStdout = Join-Path $output 'client.stdout.log'
$clientStderr = Join-Path $output 'client.stderr.log'
$resultPath = Join-Path $output 'ipc-result.json'
$serviceProcess = $null
$hostArguments = '--diagnostic --pipe-name "{0}" --state-root "{1}" --duration-seconds {2}' -f $pipeName, $stateRoot, $HostDurationSeconds
$hostStartInfo = New-Object System.Diagnostics.ProcessStartInfo
$hostStartInfo.FileName = $service
$hostStartInfo.Arguments = $hostArguments
$hostStartInfo.UseShellExecute = $false
$hostStartInfo.CreateNoWindow = $true
$hostStartInfo.RedirectStandardOutput = $true
$hostStartInfo.RedirectStandardError = $true
$serviceProcess = New-Object System.Diagnostics.Process
$serviceProcess.StartInfo = $hostStartInfo
if (-not $serviceProcess.Start()) { throw 'The diagnostic host process could not be started.' }
try {
    Start-Sleep -Milliseconds 1200
    if ($serviceProcess.HasExited) { throw ('The diagnostic host exited before IPC validation. Exit code: ' + $serviceProcess.ExitCode) }
    $clientArguments = '--ipc-smoke --pipe-name "{0}" --output "{1}"' -f $pipeName, $resultPath
    $client = Start-Process -FilePath $service -ArgumentList $clientArguments -PassThru -Wait -WindowStyle Hidden -RedirectStandardOutput $clientStdout -RedirectStandardError $clientStderr
    if ($client.ExitCode -ne 0) { throw ('The IPC smoke client failed with exit code ' + $client.ExitCode + '. See ' + $clientStderr) }
    if (-not $serviceProcess.WaitForExit(($HostDurationSeconds + 8) * 1000)) {
        throw ('The diagnostic host did not exit within the bounded timeout. Process ID requiring review: ' + $serviceProcess.Id)
    }
    $serviceProcess.WaitForExit()
    $serviceProcess.Refresh()
    if (-not $serviceProcess.HasExited) { throw ('The diagnostic host exit could not be confirmed. Process ID: ' + $serviceProcess.Id) }
    $hostOutputText = $serviceProcess.StandardOutput.ReadToEnd()
    $hostErrorText = $serviceProcess.StandardError.ReadToEnd()
    Set-Content -LiteralPath $hostStdout -Value $hostOutputText -Encoding UTF8
    Set-Content -LiteralPath $hostStderr -Value $hostErrorText -Encoding UTF8
    if ($serviceProcess.ExitCode -ne 0) { throw ('The diagnostic host exited with code ' + $serviceProcess.ExitCode + '. See ' + $hostStderr) }
    $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    if ([string]$result.status -ne 'Passed') { throw 'The IPC result did not report Passed.' }
    if ([string]$result.modifyingRequestStatus -ne 'NotActive') { throw 'A modifying request was not refused as NotActive.' }
    [pscustomobject]@{
        status = 'Passed'
        pipe = 'Local current-user-only named pipe'
        ping = [string]$result.ping
        modifyingRequest = [string]$result.modifyingRequestMessage
        gracefulShutdown = $true
        hostExitCode = $serviceProcess.ExitCode
        output = $resultPath
    } | ConvertTo-Json -Depth 5
}
finally {
    if ($null -ne $serviceProcess) { $serviceProcess.Dispose() }
}
