@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Test-QuietShield.ps1" %*
exit /b %ERRORLEVEL%
