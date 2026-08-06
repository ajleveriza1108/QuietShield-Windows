@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Validate-Phase10B.ps1"
exit /b %ERRORLEVEL%
