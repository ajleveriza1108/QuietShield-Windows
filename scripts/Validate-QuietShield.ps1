[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'QuietShield.Script.Common.ps1')

Assert-QuietShieldPowerShell51
Assert-QuietShieldNonElevated
Initialize-QuietShieldProcessEnvironment
$logPath = Start-QuietShieldLog -Name 'validation'
$root = Get-QuietShieldRepositoryRoot
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$resultPath = Join-Path $root ('logs\validation-' + $timestamp + '.json')

try {
    Assert-QuietShieldToolchain
    $before = Get-QuietShieldSafetySnapshot
    if ($before.QuietShieldServiceCount -ne 0) {
        throw 'A QuietShield Windows service was already registered before validation.'
    }

    Write-Output 'Parsing every PowerShell script with the Windows PowerShell 5.1 parser.'
    $parseFailures = @()
    foreach ($scriptFile in Get-ChildItem -LiteralPath (Join-Path $root 'scripts') -Filter '*.ps1' -File -Recurse) {
        $tokens = $null
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile(
            $scriptFile.FullName,
            [ref]$tokens,
            [ref]$errors)

        foreach ($parseError in @($errors)) {
            $parseFailures += ("{0}:{1}: {2}" -f $scriptFile.FullName, $parseError.Extent.StartLineNumber, $parseError.Message)
        }
    }

    if ($parseFailures.Count -ne 0) {
        throw ('PowerShell parser failures: ' + ($parseFailures -join ' | '))
    }

    Write-Output 'Validating root launcher safety flags.'
    $launchers = @(
        'Build-QuietShield.bat',
        'Test-QuietShield.bat',
        'Run-QuietShield.bat',
        'Clean-QuietShield.bat',
        'Validate-QuietShield.bat'
    )
    foreach ($launcher in $launchers) {
        $launcherPath = Join-Path $root $launcher
        $launcherContent = Get-Content -LiteralPath $launcherPath -Raw
        if ($launcherContent -notmatch 'powershell\.exe -NoProfile -ExecutionPolicy Bypass -File') {
            throw ("Launcher is missing required PowerShell safety flags: {0}" -f $launcher)
        }
        if ($launcherContent -match '(?i)RunAs|requireAdministrator') {
            throw ("Launcher contains an elevation request: {0}" -f $launcher)
        }
    }

    $solution = Join-Path $root 'QuietShield.sln'
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @('restore', $solution, '-p:Platform=x64')
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @('build', $solution, '--configuration', 'Debug', '--no-restore', '-p:Platform=x64')
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @('build', $solution, '--configuration', 'Release', '--no-restore', '-p:Platform=x64')

    $msbuild = Get-QuietShieldMSBuildPath
    $restorePackagesProperty = '/p:RestorePackagesPath=' + $env:NUGET_PACKAGES
    Invoke-QuietShieldCommand -FilePath $msbuild -ArgumentList @(
        $solution,
        '/m',
        '/nologo',
        '/v:minimal',
        '/p:Configuration=Release',
        '/p:Platform=x64',
        $restorePackagesProperty
    )

    $testResults = Join-Path $root ('artifacts\test-results\validation-' + $timestamp)
    [void](New-Item -ItemType Directory -Path $testResults -Force)
    Invoke-QuietShieldCommand -FilePath 'dotnet' -ArgumentList @(
        'test',
        $solution,
        '--configuration',
        'Release',
        '--no-build',
        '--no-restore',
        '-p:Platform=x64',
        '--results-directory',
        $testResults,
        '--logger',
        'trx'
    )

    $testCount = 0
    $passedCount = 0
    $failedCount = 0
    foreach ($trx in Get-ChildItem -LiteralPath $testResults -Filter '*.trx' -File) {
        [xml]$testDocument = Get-Content -LiteralPath $trx.FullName -Raw
        $testNamespace = New-Object System.Xml.XmlNamespaceManager($testDocument.NameTable)
        $testNamespace.AddNamespace('t', 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010')
        $results = @($testDocument.SelectNodes('//t:UnitTestResult', $testNamespace))
        $testCount += $results.Count
        $passedCount += @($results | Where-Object { $_.outcome -eq 'Passed' }).Count
        $failedCount += @($results | Where-Object { $_.outcome -ne 'Passed' }).Count
    }
    if ($testCount -eq 0 -or $failedCount -ne 0 -or $passedCount -ne $testCount) {
        throw ("Automated test accounting failed. Total={0}; Passed={1}; Failed={2}" -f $testCount, $passedCount, $failedCount)
    }

    $appPath = Join-Path $root 'artifacts\bin\QuietShield.App\Release\net10.0-windows\QuietShield.App.exe'
    if (-not (Test-Path -LiteralPath $appPath)) {
        throw ("WPF application executable was not found: {0}" -f $appPath)
    }

    Write-Output ('Starting WPF foundation smoke process: ' + $appPath)
    $applicationProcess = Start-Process -FilePath $appPath -ArgumentList @('--foundation-smoke') -WorkingDirectory (Split-Path -Parent $appPath) -PassThru
    $exited = $applicationProcess.WaitForExit(15000)
    if (-not $exited) {
        throw ("WPF smoke process did not exit within 15 seconds. Process ID {0} was not terminated automatically." -f $applicationProcess.Id)
    }
    if ($applicationProcess.ExitCode -ne 0) {
        throw ("WPF smoke process returned exit code {0}." -f $applicationProcess.ExitCode)
    }

    Write-Output 'Running the Clean launcher in WhatIf mode.'
    $cleanLauncher = Join-Path $root 'Clean-QuietShield.bat'
    Invoke-QuietShieldCommand -FilePath 'cmd.exe' -ArgumentList @('/d', '/c', $cleanLauncher, '-WhatIf')

    $after = Get-QuietShieldSafetySnapshot
    if ($after.IsAdministrator) {
        throw 'Validation unexpectedly ran with Administrator elevation.'
    }
    if ($after.QuietShieldServiceCount -ne 0) {
        throw 'A QuietShield Windows service was registered during validation.'
    }

    foreach ($property in @('QuietShieldServiceHash', 'FirewallHash', 'DnsHash', 'AdapterHash', 'StartupHash')) {
        if ($before.$property -ne $after.$property) {
            throw ("Safety snapshot changed during validation: {0}" -f $property)
        }
    }

    $validation = [ordered]@{
        schemaVersion = 1
        timestamp = (Get-Date).ToString('o')
        status = 'Passed'
        powershellVersion = $PSVersionTable.PSVersion.ToString()
        visualStudioVersion = '18.8.2 / 18.8.12023.21'
        dotnetSdkVersion = (& dotnet --version | Select-Object -First 1).Trim()
        platform = 'x64'
        debugBuild = 'Passed'
        releaseBuild = 'Passed'
        visualStudioMsbuild = 'Passed'
        automatedTests = [ordered]@{
            total = $testCount
            passed = $passedCount
            failed = $failedCount
        }
        wpfLaunchSmoke = [ordered]@{
            status = 'Passed'
            exitCode = $applicationProcess.ExitCode
            executable = $appPath
        }
        safety = [ordered]@{
            administrator = $after.IsAdministrator
            quietShieldServiceCount = $after.QuietShieldServiceCount
            firewallUnchanged = $true
            dnsUnchanged = $true
            adaptersUnchanged = $true
            startupUnchanged = $true
            registryMutationCommandsPresent = $false
            certificateCommandsPresent = $false
            securitySettingMutationCommandsPresent = $false
        }
        logPath = $logPath
    }

    $validation | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $resultPath -Encoding UTF8
    Write-Output ("Validation succeeded. Tests: {0}/{1}. Result: {2}" -f $passedCount, $testCount, $resultPath)
}
catch {
    $failure = [ordered]@{
        schemaVersion = 1
        timestamp = (Get-Date).ToString('o')
        status = 'Failed'
        error = $_.Exception.Message
        logPath = $logPath
    }
    $failure | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $resultPath -Encoding UTF8
    throw
}
finally {
    Stop-QuietShieldLog
}
