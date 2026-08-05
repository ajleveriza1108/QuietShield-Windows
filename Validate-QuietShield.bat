@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Validate-QuietShield.ps1" %*
exit /b %ERRORLEVEL%
