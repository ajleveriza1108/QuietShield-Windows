@echo off
setlocal EnableExtensions DisableDelayedExpansion
title QuietShield Windows - Integration Pack 1 Runtime Test

set "EXE=D:\Windows Projects\QuietShield-Windows\artifacts\bin\QuietShield.App\x64\Release\net10.0-windows\QuietShield.App.exe"
set "LOG=%LocalAppData%\QuietShield\Diagnostics\integration1-runtime.log"

echo ============================================================
echo QuietShield Windows - Integration Pack 1 Runtime Test
echo Data Saving + Wi-Fi + Fail-Open Native Tray
echo ============================================================
echo.
echo Run normally, NOT as Administrator.
echo.
echo This launcher runs QuietShield DIRECTLY.
echo The console stays open until QuietShield exits.
echo.
echo If the tray cannot initialize, QuietShield should remain open and
echo the X button falls back to normal close behavior.
echo.
echo Runtime diagnostic log:
echo   %LOG%
echo.

if not exist "%EXE%" (
    echo [FAILED] x64 Release EXE not found:
    echo %EXE%
    pause
    exit /b 2
)

echo [START] Launching QuietShield...
echo ------------------------------------------------------------
"%EXE%"
set "RC=%ERRORLEVEL%"
echo ------------------------------------------------------------
echo.
echo QuietShield exited with code: %RC%
echo.

if not "%RC%"=="0" (
    echo [CRASH/ERROR] QuietShield did not exit normally.
    echo.
    echo Check:
    echo   %LOG%
    echo.
    if exist "%LOG%" (
        echo Last runtime diagnostic entries:
        echo ------------------------------------------------------------
        powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-Content -LiteralPath '%LOG%' -Tail 40"
        echo ------------------------------------------------------------
    ) else (
        echo No QuietShield runtime log was created.
        echo If needed, Windows Application Event Log is the next evidence source.
    )
) else (
    echo [PASS] QuietShield exited normally.
)

echo.
pause
exit /b %RC%
