@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Validate-Phase11.ps1"
exit /b %ERRORLEVEL%
