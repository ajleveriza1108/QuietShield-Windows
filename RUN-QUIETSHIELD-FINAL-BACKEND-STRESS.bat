@echo off
setlocal EnableExtensions

set "REPO=D:\Windows Projects\QuietShield-Windows"
set "PROJECT=%REPO%\src\QuietShield.FinalBackendLab\QuietShield.FinalBackendLab.csproj"
set "RESULT=D:\QuietShield-Backend-Work\FINAL-BACKEND-STRESS-RESULT.json"

cd /d "%REPO%"
title QuietShield Backend Pack 5-8 Stress Test

echo ============================================================
echo QuietShield Backend Pack 5-8 - Stress Test
echo ============================================================
echo.
echo Run normally, NOT as Administrator.
echo.
echo Exercises:
echo - Parent/Child policy, PIN derivation and tamper-evident policies
echo - Private Browser session isolation, tracker and navigation policy
echo - real local File Safety SHA-256/header/MOTW inspection
echo - website safety policy
echo - signed licensing and universal device-policy validation
echo - signed update-manifest and package verification
echo - final backend invariant audit
echo.
echo It DOES NOT change Windows accounts, terminate programs, change
echo Firewall/DNS, install an update, contact a licence server, or
echo start/stop a Windows service.
echo.

set /p "SECONDS=Stress duration in seconds [default 300, max 3600]: "
if "%SECONDS%"=="" set "SECONDS=300"

echo.
echo Building Final Backend Lab...
dotnet.exe build "%PROJECT%" -c Release --nologo
if errorlevel 1 (
    echo [FAILED] Final Backend Lab build failed.
    pause
    exit /b 1
)

echo.
echo Starting final backend stress test for %SECONDS% seconds...
dotnet.exe run --project "%PROJECT%" -c Release --no-build -- --seconds %SECONDS% --output "%RESULT%"
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
    echo [PASS] Final backend stress test passed.
) else (
    echo [REVIEW] Final backend stress test reported a failure.
)

echo Result:
echo %RESULT%
pause
exit /b %RC%
