@echo off
setlocal
title QuietShield Phase 12 Installer Rehearsal

echo ============================================================
echo QuietShield Windows Phase 12 Installer Rehearsal
echo ============================================================
echo.
echo This launcher does not elevate itself.
echo Right-click this BAT file and choose "Run as administrator".
echo The unsigned beta must remain subject to Windows security checks.
echo.

fltmc.exe >nul 2>&1
if errorlevel 1 (
    echo [STOP] This console is not elevated.
    echo Close it, then right-click this BAT file and choose "Run as administrator".
    pause
    exit /b 1
)

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Run-Phase12-Installer-Rehearsal.ps1"
set "QuietShieldExitCode=%ERRORLEVEL%"
echo.
if not "%QuietShieldExitCode%"=="0" echo QuietShield Phase 12 rehearsal stopped with exit code %QuietShieldExitCode%.
if "%QuietShieldExitCode%"=="0" echo QuietShield Phase 12 rehearsal completed.
pause
exit /b %QuietShieldExitCode%
