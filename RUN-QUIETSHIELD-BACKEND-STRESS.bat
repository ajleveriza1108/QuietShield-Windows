@echo off
setlocal EnableExtensions

set "REPO=D:\Windows Projects\QuietShield-Windows"
set "PROJECT=%REPO%\src\QuietShield.BackendLab\QuietShield.BackendLab.csproj"
set "RESULT=D:\QuietShield-Backend-Work\BACKEND-STRESS-RESULT.json"

cd /d "%REPO%"
title QuietShield Backend Pack 1-4 Stress Test

echo ============================================================
echo QuietShield Backend Pack 1-4 - Stress Test
echo ============================================================
echo.
echo Run normally, NOT as Administrator.
echo.
echo This stress test:
echo - exercises backend health/recovery supervision
echo - runs the real DNS filtering proxy on an ephemeral LOOPBACK port
echo - proves configured DNS blocks with local NXDOMAIN responses
echo - repeatedly evaluates the protection automation engine
echo - samples real Windows TCP/UDP/interface telemetry
echo - observes QuietShieldService if Live Dev Mode is enabled
echo.
echo It DOES NOT change adapter DNS, Firewall rules, services, WFP, startup,
echo or Windows security settings.
echo.

set /p "SECONDS=Stress duration in seconds [default 120, max 3600]: "
if "%SECONDS%"=="" set "SECONDS=120"

echo.
echo Building Backend Lab...
dotnet.exe build "%PROJECT%" -c Release --nologo
if errorlevel 1 (
  echo [FAILED] Backend Lab build failed.
  pause
  exit /b 1
)

echo.
echo Starting stress test for %SECONDS% seconds...
dotnet.exe run --project "%PROJECT%" -c Release --no-build -- --seconds %SECONDS% --output "%RESULT%"
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
  echo [PASS] Backend stress test passed.
) else (
  echo [REVIEW] Backend stress test reported a failure.
)

echo Result:
echo %RESULT%
pause
exit /b %RC%
